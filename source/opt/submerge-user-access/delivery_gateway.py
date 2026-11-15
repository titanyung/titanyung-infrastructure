#!/usr/bin/env python3
"""Loopback-only subscription gate. Explicit upstream allow-list is mandatory."""
from __future__ import annotations
import argparse
from dataclasses import dataclass,field
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

from identity import IdentityError,IdentityResolver,slug_from_path
from lifecycle import LifecycleStore
from purge_codecs import empty_provider,infer_format,render_purge

UPSTREAM_HEADER='x-user-access-upstream'
HOP=frozenset({'connection','keep-alive','proxy-authenticate','proxy-authorization',
              'te','trailer','transfer-encoding','upgrade','proxy-connection'})


class GatewayError(ValueError):pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


class GatewayPolicy:
    def __init__(self,allowed_upstreams,*,timeout_seconds=15,max_response_bytes=8*1024*1024):
        if not isinstance(allowed_upstreams,list) or not allowed_upstreams:raise GatewayError('explicit_upstream_policy_required')
        self.rules=[]
        for item in allowed_upstreams:
            if not isinstance(item,dict) or item.get('scheme') not in {'http','https'} or item.get('host')!='127.0.0.1' or type(item.get('port')) is not int or not 1<=item['port']<=65535 or item['port'] in {31878,18131} or item.get('path_prefix') not in {'/sub/','/merge/'}:
                raise GatewayError('invalid_loopback_upstream_policy')
            verify=item.get('verify_tls',True)
            if type(verify) is not bool:raise GatewayError('invalid_tls_policy')
            self.rules.append(dict(item,verify_tls=verify))
        if type(timeout_seconds) is not int or not 1<=timeout_seconds<=60 or type(max_response_bytes) is not int or not 1024<=max_response_bytes<=32*1024*1024:raise GatewayError('invalid_gateway_bounds')
        self.timeout_seconds=timeout_seconds;self.max_response_bytes=max_response_bytes

    @classmethod
    def from_file(cls,path):
        value=json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(value,dict):raise GatewayError('invalid_gateway_policy')
        return cls(value.get('allowed_upstreams'),timeout_seconds=value.get('timeout_seconds',15),max_response_bytes=value.get('max_response_bytes',8*1024*1024))

    def validate(self,url):
        if not isinstance(url,str) or not url or len(url)>8192 or any(ord(c)<32 or ord(c)==127 for c in url):raise GatewayError('invalid_upstream')
        parsed=urllib.parse.urlsplit(url)
        if parsed.username is not None or parsed.password is not None or parsed.fragment or parsed.hostname!='127.0.0.1':raise GatewayError('upstream_not_allowed')
        try:port=parsed.port
        except ValueError:raise GatewayError('invalid_upstream_port') from None
        slug=slug_from_path(parsed.path)
        for item in self.rules:
            if (parsed.scheme,parsed.hostname,port)==(item['scheme'],item['host'],item['port']) and parsed.path.startswith(item['path_prefix']):return item,slug
        raise GatewayError('upstream_not_allowed')


@dataclass
class GatewayResponse:
    status: int
    headers: list
    body: bytes=field(repr=False)
    claim_subject: object=field(default=None,repr=False)
    claim_id: str | None=None
    claim_generation: int | None=None
    repeat_delivery: bool=False


def end_to_end(headers,*,request=False):
    pairs=list(headers.items()) if hasattr(headers,'items') else list(headers)
    connection=set()
    for key,value in pairs:
        if key.lower()=='connection':connection.update(token.strip().lower() for token in value.split(','))
    excluded=HOP|connection|({UPSTREAM_HEADER,'host','content-length','accept-encoding'} if request else set())
    return [(key,value) for key,value in pairs if key.lower() not in excluded and not key.lower().startswith('x-user-access-')]


class DeliveryGateway:
    def __init__(self,policy,store,resolver):
        if not isinstance(policy,GatewayPolicy):raise GatewayError('explicit_upstream_policy_required')
        self.policy,self.store,self.resolver=policy,store,resolver

    @staticmethod
    def local(status,body=b'subscription unavailable\n',mime='text/plain; charset=utf-8'):
        return GatewayResponse(status,[('Content-Type',mime),('Content-Length',str(len(body))),('Cache-Control','no-store'),('X-Content-Type-Options','nosniff')],body)

    def process(self,method,target,headers):
        normalized={key.lower():value for key,value in headers.items()}
        rule,upstream_slug=self.policy.validate(normalized.get(UPSTREAM_HEADER))
        subject=self.resolver.resolve(slug_from_path(target))
        if self.resolver.resolve(upstream_slug)!=subject:raise GatewayError('upstream_identity_mismatch')
        query=urllib.parse.parse_qs(urllib.parse.urlsplit(target).query,keep_blank_values=True)
        # Determine provider semantics before any response can consume a claim.
        is_provider=str((query.get('format') or query.get('target') or [''])[0]).lower() in {'provider','clash-provider'}
        kind='provider' if is_provider else 'profile';request_id=uuid.uuid4().hex
        decision=self.store.gate(subject,method=method,kind=kind,format_name='',request_id=request_id)
        if decision.action=='block':return self.local(403,b'subscription disabled\n')
        if any(len(query.get(key,[]))>1 for key in ('format','target')):return self.local(400,b'ambiguous subscription format\n')
        if query.get('format') and query.get('target') and query['format'][0].lower()!=query['target'][0].lower():return self.local(400,b'ambiguous subscription format\n')
        if method not in {'GET','HEAD'}:return self.local(405,b'method not allowed\n')
        if decision.action=='head':return self.local(200,b'')
        if decision.action in {'empty_provider','prepare'}:
            if decision.action=='empty_provider':format_name='provider'
            else:
                try:format_name=infer_format(query,normalized.get('user-agent',''))
                except ValueError:return self.local(400,b'unsupported subscription format\n')
                if format_name=='provider':raise GatewayError('provider_semantics_mismatch')
            prepared=render_purge(format_name)
            decision=self.store.gate(subject,method=method,kind=kind,format_name=format_name,
                request_id=request_id,prepared=prepared,expected_generation=decision.generation)
            # Legacy non-manual armed rows retain their nonconsuming provider
            # behavior; repeated manual deliveries always carry a receipt.
            if decision.action=='empty_provider':
                body,mime=empty_provider();return self.local(200,body,mime)
            if decision.action not in {'purge','purge_repeat'}:return self.local(403,b'subscription disabled\n')
            response=self.local(200,decision.response.body,decision.response.content_type)
            response.claim_subject=subject;response.claim_id=decision.claim_id
            response.claim_generation=(decision.generation
                if decision.reason in {'manual_subscription_disabled','restoration_pending'} else None)
            response.repeat_delivery=decision.action=='purge_repeat'
            return response
        if decision.action!='allow':raise GatewayError('unexpected_gate_decision')
        return self.forward(method,normalized[UPSTREAM_HEADER],headers,rule)

    def forward(self,method,url,headers,rule):
        forwarded=dict(end_to_end(headers,request=True));forwarded['Accept-Encoding']='identity'
        request=urllib.request.Request(url,method=method,headers=forwarded)
        context=ssl.create_default_context()
        if rule['scheme']=='https' and not rule['verify_tls']:context=ssl._create_unverified_context()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context))
        try:
            try:upstream=opener.open(request,timeout=self.policy.timeout_seconds)
            except urllib.error.HTTPError as error:upstream=error
            with upstream:
                body=upstream.read(self.policy.max_response_bytes+1)
                if len(body)>self.policy.max_response_bytes:raise GatewayError('upstream_response_too_large')
                response_headers=end_to_end(upstream.headers)
                if method!='HEAD':
                    response_headers=[(key,value) for key,value in response_headers if key.lower()!='content-length']
                    response_headers.append(('Content-Length',str(len(body))))
                return GatewayResponse(upstream.status,response_headers,body)
        except (OSError,urllib.error.URLError,TimeoutError,GatewayError):return self.local(502,b'subscription temporarily unavailable\n')

    def delivery_finished(self,response,succeeded):
        if response.claim_id is not None:
            if response.repeat_delivery:
                self.store.disabled_delivery_result(response.claim_subject,response.claim_id,
                    response.claim_generation,succeeded=succeeded)
            else:
                try:
                    self.store.delivery_result(response.claim_subject,response.claim_id,succeeded=succeeded)
                finally:
                    if response.claim_generation is not None:
                        self.store.disabled_delivery_result(response.claim_subject,response.claim_id,
                            response.claim_generation,succeeded=succeeded)


def make_server(policy,store,resolver,host='127.0.0.1',port=18131):
    if host!='127.0.0.1' or type(port) is not int or not 0<=port<=65535:raise GatewayError('gateway_must_bind_loopback')
    if port and any(item['port']==port for item in policy.rules):raise GatewayError('recursive_gateway_upstream')
    gateway=DeliveryGateway(policy,store,resolver)
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def serve_request(self):
            self.close_connection=True;response=None
            try:
                response=gateway.process(self.command,self.path,self.headers)
            except IdentityError as error:response=gateway.local(503 if str(error)=='identity_store_unavailable' else 404)
            except (GatewayError,ValueError):response=gateway.local(400)
            except Exception:response=gateway.local(503,b'subscription temporarily unavailable\n')
            succeeded=False
            try:
                self.send_response_only(response.status)
                for key,value in response.headers:self.send_header(key,value)
                self.send_header('Connection','close');self.end_headers()
                if self.command!='HEAD':self.wfile.write(response.body)
                self.wfile.flush();succeeded=True
            except (BrokenPipeError,ConnectionResetError,OSError):pass
            finally:
                try:gateway.delivery_finished(response,succeeded)
                except Exception:
                    # Durable grace deadline still releases the revocation job.
                    pass
        do_GET=do_HEAD=do_POST=do_PUT=do_DELETE=serve_request
    server=ThreadingHTTPServer((host,port),Handler)
    server.gateway=gateway
    return server


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy',required=True);parser.add_argument('--port',type=int,default=18131)
    parser.add_argument('--store',default='/var/lib/submerge-user-access/control.db')
    parser.add_argument('--sui-db',default='/usr/local/s-ui/db/s-ui.db')
    parser.add_argument('--aliases-path',default='/etc/nginx/conf.d/submerge-delivery-format-map.conf')
    args=parser.parse_args()
    server=make_server(GatewayPolicy.from_file(args.policy),LifecycleStore(args.store),IdentityResolver(args.sui_db,args.aliases_path),port=args.port)
    server.serve_forever()


if __name__=='__main__':main()

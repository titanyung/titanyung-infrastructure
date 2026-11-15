"""Private pool control and bounded per-node exit qualification.

Caller owns the current verified authority observer. No stale JSON is promoted
to an ACK, and this module never updates a proxy client's mode or TUN.
"""
import hashlib,ipaddress,json,subprocess,time,urllib.parse,urllib.request
import provider_pool as policy

def private_request(config):
    address=config['external-controller']
    policy.need(address.startswith('127.0.0.1:'),'pool_api_must_be_loopback')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(method,path,payload=None):
        headers={'Authorization':'Bearer '+config['secret']};data=None
        if payload is not None:data=json.dumps(payload).encode();headers['Content-Type']='application/json'
        req=urllib.request.Request('http://'+address+path,data=data,headers=headers,method=method)
        with opener.open(req,timeout=5) as response:raw=response.read(2*1024*1024+1)
        policy.need(len(raw)<=2*1024*1024,'pool_api_response_limit')
        return json.loads(raw) if raw else {}
    return request

def _path(name):return '/proxies/'+urllib.parse.quote(name,safe='')

def apply_gates(decisions,request,*,guard):
    """guard re-reads current config/process/authority, not a static lambda.

    Its result must bind actual pool runtime and both front observations. A
    changed authority closes all gates instead of preserving an old opening.
    """
    baseline=guard()
    need=policy.need
    need(isinstance(baseline,dict) and baseline.get('verified') is True and
         all(baseline.get(k) for k in ('config_sha256','process_identity','authority_sha256')),'verified_pool_runtime_required')
    changed=[]
    def close_all():
        for region in policy.REGIONS:request('PUT',_path(policy.GATES[region]),{'name':'REJECT'})
    for region in policy.REGIONS:
        name=policy.GATES[region];wanted=decisions[region]['selected']
        need(wanted in ('REJECT',policy.FAST[region]),'invalid_pool_gate_selection')
        if guard()!=baseline:
            close_all();raise RuntimeError('pool_authority_changed_closed')
        if request('GET',_path(name)).get('now')!=wanted:
            request('PUT',_path(name),{'name':wanted})
            if request('GET',_path(name)).get('now')!=wanted:
                close_all();raise RuntimeError('pool_gate_ack_failed_closed')
            changed.append(name)
    if guard()!=baseline:
        close_all();raise RuntimeError('pool_authority_changed_closed')
    return {'status':'confirmed','gates':{r:decisions[r]['selected'] for r in policy.REGIONS},
            'changed':changed,'authority_sha256':baseline['authority_sha256'],
            'client_mode_changed':False,'service_restarted':False}

def qualify(proxy,*,request,socks_port,guard,now=None,selector_tag='PAOLUZ_QUALIFICATION_PROBE'):
    """Caller serializes this dedicated selector; never use a user selector.

    Two small HTTPS observations, no speed/download load. Always resets probe
    to REJECT, including exceptions. Native TLS verification remains enabled.
    """
    policy.need(type(socks_port) is int and 1024<=socks_port<=65535,'probe_port')
    baseline=guard()
    policy.need(isinstance(baseline,dict) and baseline.get('verified') is True and baseline.get('config_sha256'),'verified_probe_runtime_required')
    policy.need(selector_tag in ('PAOLUZ_QUALIFICATION_PROBE',*(f'PAOLUZ_QUALIFICATION_PROBE_{i}' for i in range(4))),'dedicated_probe_selector_required')
    tag=selector_tag;checks=[]
    try:
        request('PUT',_path(tag),{'name':'UPSTREAM::'+proxy['name']})
        policy.need(request('GET',_path(tag)).get('now')=='UPSTREAM::'+proxy['name'],'probe_selector_not_confirmed')
        for source,url in (('cloudflare','https://www.cloudflare.com/cdn-cgi/trace'),('ipinfo','https://ipinfo.io/json')):
            if guard()!=baseline:raise RuntimeError('probe_authority_changed')
            args=['curl','-q','--noproxy','','--socks5-hostname','127.0.0.1:'+str(socks_port),
                  '--silent','--show-error','--fail','--connect-timeout','3','--max-time','6','--max-filesize','16384',url]
            try:
                p=subprocess.run(args,capture_output=True,timeout=8)
                policy.need(p.returncode==0 and len(p.stdout)<=16384,'probe_request_failed')
                if source=='cloudflare':
                    data=dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)
                    address,country=data.get('ip'),data.get('loc')
                else:
                    data=json.loads(p.stdout);address,country=data.get('ip'),data.get('country')
                policy.need(ipaddress.ip_address(address).is_global,'probe_address_not_global')
                checks.append({'source':source,'success':True,'ip':address,'country':country,'checked_at':int(time.time()) if now is None else now})
            except (OSError,subprocess.TimeoutExpired,ValueError,KeyError):
                checks.append({'source':source,'success':False,'checked_at':int(time.time()) if now is None else now})
        if guard()!=baseline:raise RuntimeError('probe_authority_changed')
    finally:
        request('PUT',_path(tag),{'name':'REJECT'})
    return {'node_sha256':policy.digest(proxy),'status':'completed','checked_at':int(time.time()) if now is None else now,
            'checks':checks,'pool_runtime_sha256':baseline['config_sha256']}

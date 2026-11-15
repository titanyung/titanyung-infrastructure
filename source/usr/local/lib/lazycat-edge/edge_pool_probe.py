"""Read-only loopback SG fallback qualification, only called for V4 all-owned-bad."""
import argparse,ipaddress,json,subprocess,tempfile,time
from pathlib import Path

def probe(port=18331):
    if type(port) is not int or not 1024<=port<=65535:raise ValueError('invalid_pool_port')
    checks=[]
    with tempfile.TemporaryDirectory(prefix='owned-sg-pool-probe-') as folder:
        for host in ('chatgpt.com','claude.ai'):
            path=Path(folder)/host
            proc=subprocess.run(['curl','-q','-4','--silent','--show-error','--noproxy','',
                '--socks5-hostname','127.0.0.1:'+str(port),'--connect-timeout','3','--max-time','6',
                '--max-filesize','65536','--output',str(path),'--write-out','%{json}',
                'https://'+host+'/cdn-cgi/trace'],capture_output=True,text=True,timeout=8)
            try:metrics=json.loads(proc.stdout)
            except ValueError:metrics={}
            values={}
            if path.exists():
                for line in path.read_text(errors='replace').splitlines():
                    if '=' in line:
                        key,value=line.split('=',1)
                        if key in ('ip','loc','h'):values[key]=value
            try:address=ipaddress.ip_address(values.get('ip'));global_v4=address.version==4 and address.is_global
            except (TypeError,ValueError):global_v4=False
            healthy=proc.returncode==0 and metrics.get('http_code')==200 and metrics.get('ssl_verify_result')==0 \
                and values.get('loc')=='SG' and values.get('h')==host and global_v4
            checks.append({'site':host,'healthy':bool(healthy),'http_status':metrics.get('http_code'),
                'returncode':proc.returncode,'tls_verify_result':metrics.get('ssl_verify_result'),
                'ip':values.get('ip'),'loc':values.get('loc'),'time_seconds':metrics.get('time_total')})
    return {'region':'SG','healthy':all(r['healthy'] for r in checks),'checks':checks,'checked_at':int(time.time())}

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=18331)
    print(json.dumps(probe(parser.parse_args().port)))

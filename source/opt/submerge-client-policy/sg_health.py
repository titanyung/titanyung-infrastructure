"""Maintain server-only SG reachability metadata; never operates a client."""
import argparse, concurrent.futures, json, os, tempfile, time, urllib.parse, urllib.request
from pathlib import Path

TAGS=('uzuma-singtel','zoro-sg','lazycat-starhub')

def api_details(runtime):
    doc=json.loads(Path(runtime).read_bytes())
    api=doc['experimental']['clash_api']
    address=api['external_controller']
    if not address.startswith('127.0.0.1:') or not str(address.split(':')[1]).isdigit():
        raise ValueError('health_api_not_loopback')
    return 'http://'+address,api['secret']

def request(base,secret,path,payload=None):
    headers={'Authorization':'Bearer '+secret}
    data=None
    if payload is not None:
        data=json.dumps(payload).encode();headers['Content-Type']='application/json'
    query=urllib.request.Request(base+path,data=data,headers=headers,
        method='PATCH' if payload is not None else 'GET')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(query,timeout=8) as response:
        raw=response.read(8192)
        return json.loads(raw) if raw else {}

def probe(base,secret,tag):
    query=urllib.parse.urlencode({'url':'https://www.gstatic.com/generate_204','timeout':6000})
    try:
        value=request(base,secret,'/proxies/'+tag+'/delay?'+query)
        return type(value.get('delay')) is int and value['delay']>=0
    except Exception:
        return False

def choose_mode(healthy):
    return 'ai-z'+str(int(bool(healthy.get('zoro-sg'))))+'s'+str(int(bool(healthy.get('uzuma-singtel'))))+'l'+str(int(bool(healthy.get('lazycat-starhub'))))

def egress_checks(path='/run/dmit-client-policy/egress.json',now=None):
    """A connected AI path must also use its intended access network."""
    now=int(time.time()) if now is None else now
    try:
        value=json.loads(Path(path).read_bytes())
        fresh=value.get('schema')==1 and int(value['checked_at'])<=now+10 and 0<=now-int(value['checked_at'])<=120 and now<int(value['expires_at'])
        return {tag:bool(fresh and value['routes'].get(tag,{}).get('verified') is True) for tag in TAGS}
    except Exception:return {tag:False for tag in TAGS}

def write_state(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,name=tempfile.mkstemp(dir=str(path.parent),prefix='.health-')
    try:
        with os.fdopen(fd,'w') as stream:
            if hasattr(os,'fchmod'):os.fchmod(stream.fileno(),0o600)
            else:os.chmod(name,0o600)
            json.dump(value,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def cycle(runtime,state_path,previous=None,*,immediate=False):
    base,secret=api_details(runtime)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures={tag:pool.submit(probe,base,secret,tag) for tag in TAGS}
        observations={tag:future.result() for tag,future in futures.items()}
    previous=previous or {}
    exits=egress_checks()
    failures={tag:0 if observations[tag] else int(previous.get('failures',{}).get(tag,0))+1 for tag in TAGS}
    successes={tag:int(previous.get('successes',{}).get(tag,0))+1 if observations[tag] else 0 for tag in TAGS}
    healthy={}
    for tag in TAGS:
        was=bool(previous.get('healthy',{}).get(tag,False))
        if immediate or not previous:
            healthy[tag]=observations[tag]
        elif was:
            healthy[tag]=failures[tag]<2
        else:
            healthy[tag]=successes[tag]>=2
    # Wrong or unverified AI exit fails closed immediately; connectivity alone
    # must never validate a provider's data-centre fallback. Normal site traffic
    # from that same VPS is intentionally outside this AI-specific check.
    healthy={tag:healthy[tag] and (exits[tag] if tag!='lazycat-starhub' else True) for tag in TAGS}
    mode=choose_mode(healthy)
    actual=request(base,secret,'/configs').get('mode')
    if actual!=mode:request(base,secret,'/configs',{'mode':mode})
    verified=request(base,secret,'/configs').get('mode')
    if verified!=mode:raise ValueError('health_state_not_applied')
    value={'mode':mode,'healthy':healthy,'observed':observations,'ai_exit_verified':exits,'failures':failures,
           'successes':successes,'updated_at':int(time.time())}
    write_state(state_path,value)
    return value

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--runtime',default='/run/dmit-direct-staging/config.json')
    parser.add_argument('--state',default='/run/dmit-client-policy/health.json')
    parser.add_argument('--once',action='store_true');args=parser.parse_args()
    previous=None
    while True:
        try:
            previous=cycle(args.runtime,args.state,previous,immediate=args.once)
            if args.once:print(json.dumps(previous));return
        except Exception as error:
            print('sg_health_cycle_failed '+type(error).__name__,flush=True)
            if args.once:raise
        time.sleep(5)

if __name__=='__main__':main()

"""Independent main-policy selector control; no Clash-mode writes or restarts."""
import copy,json,urllib.parse,urllib.request
import server_route_policy as policy

def set_selections(contract,qualified_health,request,*,guard,category_health=None,only=None):
    # The caller proves the desired-account ACK, config hash and generation.
    # Recheck around every control mutation so a stale observer cannot control
    # a newly installed authority generation.
    baseline=guard()
    if not isinstance(baseline,dict) or baseline.get('verified') is not True or not all(
        key in baseline for key in ('generation','cohort_sha256','runtime_sha256')):
        raise RuntimeError('verified_business_generation_required')
    desired=policy.desired_selections(contract,qualified_health,category_health=category_health)
    if only is not None:
        if not isinstance(only,(set,frozenset,list,tuple)) or not set(only)<=set(desired):raise ValueError('unreviewed_business_selector_scope')
        desired={tag:value for tag,value in desired.items() if tag in only}
    changed=[]
    for tag,wanted in desired.items():
        path='/proxies/'+urllib.parse.quote(tag,safe='')
        current=request('GET',path,None)
        if current.get('now')!=wanted:
            if guard()!=baseline:raise RuntimeError('business_generation_changed')
            request('PUT',path,{'name':wanted})
            check=request('GET',path,None)
            if check.get('now')!=wanted:raise RuntimeError('business_selector_not_confirmed')
            changed.append(tag)
    if guard()!=baseline:raise RuntimeError('business_generation_changed')
    return {'status':'confirmed','selectors':copy.deepcopy(desired),'changed':changed,
        'clash_mode_changed':False,'service_restarted':False}

def private_request(runtime):
    api=runtime['experimental']['clash_api'];address=api['external_controller']
    if not address.startswith('127.0.0.1:'):raise ValueError('private_control_api_required')
    base='http://'+address;secret=api['secret'];opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def request(method,path,payload):
        headers={'Authorization':'Bearer '+secret};raw=None
        if payload is not None:raw=json.dumps(payload).encode();headers['Content-Type']='application/json'
        req=urllib.request.Request(base+path,data=raw,headers=headers,method=method)
        with opener.open(req,timeout=4) as response:body=response.read(65537)
        if len(body)>65536:raise ValueError('control_response_limit')
        return json.loads(body) if body else {}
    return request

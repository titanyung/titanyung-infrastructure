"""LC tiny read-only direct-path probe, standard library only; no pool daemon."""
import json,time,urllib.error,urllib.parse,urllib.request

def run(config_path,tag):
    unknown={'status':'unknown','completed':False,'observed_at':int(time.time())}
    delay_attempted=False
    try:
        if tag!='direct':return unknown
        with open(config_path) as stream:config=json.load(stream)
        api=config['experimental']['clash_api'];address=api['external_controller']
        if not address.startswith('127.0.0.1:') or not any(r.get('tag')==tag and r.get('type')=='direct' for r in config['outbounds']):return unknown
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(path):
            req=urllib.request.Request('http://'+address+path,headers={'Authorization':'Bearer '+api['secret']})
            with opener.open(req,timeout=7) as response:return json.loads(response.read(8192))
        if request('/proxies/direct').get('name')!='direct':return unknown
        delay_attempted=True
        result=request('/proxies/direct/delay?'+urllib.parse.urlencode({'url':'https://www.gstatic.com/generate_204','timeout':5000}))
        if type(result.get('delay')) is int and result['delay']>0:return {'status':'healthy','completed':True,'observed_at':int(time.time()),'delay_ms':result['delay']}
    except urllib.error.HTTPError as error:
        try:body=json.loads(error.read(8192))
        except Exception:return unknown
        if delay_attempted and (error.code==504 or error.code==503 and body.get('message')=='An error occurred in the delay test'):return {'status':'failed','completed':True,'observed_at':int(time.time())}
    except Exception:pass
    return unknown

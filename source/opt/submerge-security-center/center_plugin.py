"""Seven security views backed by the existing authenticated lifecycle and mail APIs."""
import hashlib,hmac,json,os,re,secrets,sqlite3,stat,subprocess,time,uuid
from contextlib import closing
from pathlib import Path
from flask import Response,g,jsonify,request

ASSETS=Path(os.environ.get('CENTER_ASSET_DIR',Path(__file__).parent/'assets'))
NODE_REPORT=Path('/var/lib/submerge-security-center/nodes.json')
AUDIT_DB=Path('/var/lib/submerge-security-center/audit.sqlite3')
PAGES=(('overview','安全总览'),('users','用户与订阅'),('events','风险事件'),('nodes','节点防护'),
       ('notifications','通知中心'),('audit','永久操作审计'),('settings','后台设置'))
MUTATIONS={'/api/admin-password':'修改后台密码','/api/totp/bind':'绑定二次验证','/api/totp/unbind':'解绑二次验证',
           '/api/violation-mail/config':'修改发信配置','/api/violation-mail/test':'发送测试通知',
           '/api/center/nodes/refresh':'重新核查节点防护'}

class PermanentAudit:
    def __init__(self,path=AUDIT_DB):
        self.path=Path(path);self.path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        if not self.path.exists():
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
        info=self.path.lstat()
        if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_mode&0o077:raise ValueError('audit_permissions')
        with sqlite3.connect(self.path) as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS audit_log(
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT NOT NULL UNIQUE,
              at INTEGER NOT NULL,username TEXT NOT NULL,actor TEXT NOT NULL,
              action TEXT NOT NULL,details_json TEXT NOT NULL);
              CREATE TRIGGER IF NOT EXISTS no_update BEFORE UPDATE ON audit_log
              BEGIN SELECT RAISE(ABORT,'permanent_audit_is_append_only'); END;
              CREATE TRIGGER IF NOT EXISTS no_delete BEFORE DELETE ON audit_log
              BEGIN SELECT RAISE(ABORT,'permanent_audit_is_append_only'); END;''')
    def append(self,actor,action,*,target='',details=None,event_id=None):
        event_id=event_id or uuid.uuid4().hex
        with sqlite3.connect(self.path,timeout=3) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM audit_log WHERE event_id=?',(event_id,)).fetchone():return
            db.execute('INSERT INTO audit_log(event_id,at,username,actor,action,details_json) VALUES(?,?,?,?,?,?)',
                (event_id,int(time.time()),target[:160],actor[:120],action[:120],json.dumps(details or {},ensure_ascii=False)))

def node_report(path=NODE_REPORT):
    try:
        value=json.loads(Path(path).read_bytes())
        from node_inventory import expected_keys,REVISION
        expected=expected_keys()
        if value.get('schema')!=1:raise ValueError('report_shape')
        if expected is None:
            if len(value.get('peers',[]))!=6:raise ValueError('report_shape')
        elif (value.get('routing_revision')!=REVISION or
              {r.get('key') for r in value.get('peers',[])}!=expected or len(value.get('peers',[]))!=len(expected)):
            raise ValueError('revision_report_inventory')
        value['stale']=int(time.time())-int(value['checked_at'])>900
        if value['stale']:
            for row in value['peers']:row['status']='stale'
        return value
    except Exception:return {'schema':1,'checked_at':None,'stale':True,'peers':[],'error':'节点核查尚未完成'}

def native_users():
    try:
        value=json.loads(Path('/run/dmit-direct-staging/config.json').read_bytes())
        rows=[x for x in value['inbounds'] if x.get('type')=='anytls']
        from network_runtime import expected_fronts,load_network_plan
        if {x.get('tag') for x in rows}!=set(expected_fronts(load_network_plan())):raise ValueError('native_inventory_changed')
        values=[{u['name'] for u in row.get('users',[])} for row in rows]
        return set.intersection(*values),set.union(*values),True
    except Exception:return set(),set(),False

def inventory(backend):
    from new_enrollment import DB
    with sqlite3.connect('file:'+str(DB)+'?mode=ro',uri=True,timeout=3) as db:
        metadata={str(row[0]):{'description':str(row[1] or '')[:240]} for row in db.execute('SELECT name,desc FROM clients')}
    both,some,available=native_users();rows=[]
    for identity in backend.list_users():
        name=identity['username'];target=identity['target_id']
        state=backend.state(backend.subject(target)) or {'state':'active'}
        current=state['state'];enabled=identity.get('enabled',True)
        subscription='正常' if current=='active' and enabled else 'S-UI已禁用' if current=='active' else '等待下次更新停用' if current=='armed' else '持续下发停用配置' if current in ('purge_issued','revoking','revoked') else '恢复处理中'
        presence='待核查' if not available else '入口状态不一致' if name in some and name not in both else '专用入口已载入' if name in both else '专用入口未载入'
        if current=='revoked':presence='已撤销并验证' if available and name not in some else '撤销结果待复核'
        elif current=='revoking':presence='撤销处理中'
        elif current in ('restoring','restore_pending'):presence='恢复处理中'
        if not enabled and name in some:presence='S-UI禁用，入口仍有凭据'
        rows.append({'client_id':target,'username':name,'description':metadata.get(name,{}).get('description',''),
            'enabled':enabled,'eligible':identity.get('eligible',False),'unavailable_reason':identity.get('unavailable_reason',''),
            'state':current,'subscription_state':subscription,'forwarding_state':presence,
            'selectable':identity.get('eligible',False) and current=='active',
            'restorable':current in ('armed','purge_issued','revoking','revoked'),
            'updated_at':state.get('updated_at'),'error':state.get('last_error_code')})
    return rows

def audit_page(backend,audit):
    from access_policy import DEFAULT_DB
    limit=50;username=request.args.get('user','')[:160];category=request.args.get('category','all')
    if category not in ('all','business','acceptance'):raise ValueError('audit_category')
    actor_type=request.args.get('actor_type','all')
    if actor_type not in ('all','manual','automatic'):raise ValueError('audit_actor')
    raw=request.args.get('before','')
    cursor=json.loads(raw) if raw else [9223372036854775807,'z',9223372036854775807]
    if not isinstance(cursor,list) or len(cursor)!=3 or type(cursor[0]) is not int or type(cursor[2]) is not int or cursor[1] not in ('z','control','settings','lazycat'):raise ValueError('audit_cursor')
    result=[]
    from lazycat_accounts import DB_PATH as LAZYCAT_AUDIT_DB
    lazycat_service=request.environ.get('lazycat_accounts_service')
    lazycat_path=lazycat_service.store.path if lazycat_service else LAZYCAT_AUDIT_DB
    for source,path in [('control',Path(os.environ.get('USER_ACCESS_CONTROL_DB',DEFAULT_DB))),('settings',audit.path),('lazycat',lazycat_path)]:
        with closing(sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=3)) as db:
            db.row_factory=sqlite3.Row
            where=['(at<? OR (at=? AND (?<? OR (?=? AND sequence<?))))']
            args=[cursor[0],cursor[0],source,cursor[1],source,cursor[1],cursor[2]]
            if username:where.append('username=?');args.append(username)
            if category=='acceptance':where.append("(actor LIKE 'codex-%' OR username LIKE 'codex-zoro-qa-%')")
            elif category=='business':where.append("(actor NOT LIKE 'codex-%' AND username NOT LIKE 'codex-zoro-qa-%')")
            if actor_type=='manual':where.append("actor='admin'")
            elif actor_type=='automatic':where.append("actor<>'admin'")
            query='SELECT sequence,at,username,actor,action,details_json FROM audit_log WHERE '+' AND '.join(where)+' ORDER BY at DESC,sequence DESC LIMIT ?'
            for row in db.execute(query,[*args,limit+1]):
                record=dict(row);record['source']=source
                try:record['details']=json.loads(record.pop('details_json'))
                except ValueError:record['details']={};record.pop('details_json',None)
                result.append(record)
    result.sort(key=lambda x:(x['at'],x['source'],x['sequence']),reverse=True)
    more=len(result)>limit;result=result[:limit]
    return {'events':result,'permanent':True,'has_more':more,'next_before':
        [result[-1]['at'],result[-1]['source'],result[-1]['sequence']] if more else None}

def render_html(html):
    nav=''.join('<a href="#/'+key+'" data-sc-nav="'+key+'">'+name+'</a>' for key,name in PAGES)
    options=''.join('<option value="'+key+'">'+name+'</option>' for key,name in PAGES)
    shell='<div id="security-center-v2" data-security-center="v2"><aside class="sc-sidebar"><div class="sc-brand">安全中心</div><nav aria-label="安全中心页面">'+nav+'</nav><div class="sc-zone">新加坡时间 · UTC+08</div></aside><main><label class="sc-mobile-picker">页面<select id="sc-page-picker">'+options+'</select></label>'
    if html.count('<main>')!=1 or html.count('</main>')!=1:raise ValueError('page_shell_anchor')
    html=html.replace('<main>',shell,1).replace('</main>','</main></div>',1)
    boot='''<link rel="stylesheet" href="./center-assets/center.css">
<script>window.SecurityCenter={page:(/^(overview|users|events|nodes|notifications|audit|settings)$/.test(location.hash.slice(2).split('?')[0])?location.hash.slice(2).split('?')[0]:'overview'),selectedUser:'',version:'20261107'};</script>
<script defer src="./center-assets/center.js"></script>'''
    html=html.replace('</head>',boot+'</head>',1)
    html=html.replace('同时修改分流规则、安全中心和香港流量后台的 admin 密码。','修改统一后台的管理员登录密码。')
    html=html.replace('修改三个后台密码','修改后台密码')
    html=html.replace('正在同步三个后台……','正在更新后台密码……').replace('请关闭三个后台页面','请关闭后台页面').replace('三个后台密码已修改','后台密码已修改')
    html=html.replace('记录用户通过搬瓦工访问的目标域名/IP和端口。','访问明细请在“流量与访问”页面按用户检索。')
    for function,pages in [('loadSubscriptionSummary',['users']),('refreshAccessHistory',[])]:
        anchor='async function '+function+'() {'
        if anchor not in html:raise ValueError('page_function_anchor_'+function)
        html=html.replace(anchor,anchor+'\n if(window.SecurityCenter&&!'+json.dumps(pages)+'.includes(window.SecurityCenter.page))return;',1)
    start=html.index('async function loadStats() {');end=html.index('// SUBMERGE_SUBSCRIPTION_HISTORY_JS',start)
    html=html[:start]+'''async function loadStats() {
 if(window.SecurityCenter&&!['overview','events'].includes(window.SecurityCenter.page))return;
 const r=await fetch('./api/stats',{cache:'no-store'});if(!r.ok)return;const data=await r.json();const links=data.links||[];
 document.getElementById('linkCount').textContent=links.length;
 document.getElementById('requestCount').textContent=links.reduce((s,x)=>s+Number(x.requests||0),0);
 document.getElementById('alertCount').textContent=links.filter(x=>x.alert).length;
 const body=document.getElementById('statsRows');body.replaceChildren();
 for(const item of links){const row=document.createElement('tr');for(const value of [item.subid,item.requests,item.mb+' MB',item.unique_ips,item.last_time||'—',item.alert?'需关注：'+(item.alerts||[]).join(' / '):'正常']){const cell=document.createElement('td');cell.textContent=String(value??'—');row.append(cell);}body.append(row);}
}

'''+html[end:]
    # Password changes now use the same second-factor header as other sensitive controls.
    anchor='"Content-Type": "application/json"'
    section_start=html.index('changeAdminPasswordButton.addEventListener')
    section_end=html.index('async function refreshTotpStatus',section_start)
    part=html[section_start:section_end]
    if anchor in part:
        part=part.replace(anchor,anchor+', [typeof sensitiveMode!=="undefined"&&sensitiveMode==="totp"?"X-TOTP-Code":"X-View-Key"]:askKey()',1)
        html=html[:section_start]+part+html[section_end:]
    for start_token,end_token in [('viewFile.addEventListener(','viewSub.addEventListener('),('async function loadFiles() {','loadStats();')]:
        start=html.index(start_token);end=html.index(end_token,start)
        part=html[start:end].replace('output.textContent','document.getElementById("sc-config-file-output").textContent')
        html=html[:start]+part+html[end:]
    return html

def register(app,html,admin_request,same_origin_request,verify_view_key,totp_enabled,backend):
    if app.extensions.get('security_center_v2'):return
    audit=PermanentAudit();app.extensions['security_center_v2']=audit
    content=render_html(html)
    def root():
        response=Response(content,content_type='text/html; charset=utf-8');response.headers['Cache-Control']='no-store';return response
    app.view_functions['index']=root
    def actor_guard():
        if not admin_request():return jsonify(error='admin_required'),403
        return None
    def mutation_guard():
        denied=actor_guard()
        if denied:return denied
        from admin_plugin import COOKIE,CSRF_HEADER,normalized_origin,public_request_origin
        if normalized_origin(request.headers.get('Origin'))!=public_request_origin() or not same_origin_request():return jsonify(error='same_origin_required'),403
        store=app.extensions['user_access_admin'];session=store.session(request.cookies.get(COOKIE),request.authorization.username)
        if session is None or not hmac.compare_digest(request.headers.get(CSRF_HEADER,''),session['csrf']):return jsonify(error='csrf_required'),403
        return None
    from lazycat_accounts import register as register_lazycat_accounts
    register_lazycat_accounts(app,actor_guard=actor_guard,mutation_guard=mutation_guard,backend=backend)
    @app.before_request
    def attach_lazycat_audit_source():
        request.environ['lazycat_accounts_service']=app.extensions['lazycat_accounts']
    @app.get('/center-assets/<name>')
    def center_asset(name):
        if name not in ('center.js','center.css'):return Response(status=404)
        response=Response((ASSETS/name).read_bytes(),content_type=('text/css' if name.endswith('.css') else 'application/javascript')+'; charset=utf-8')
        response.headers['Cache-Control']='no-store';return response
    for path,name in [('/user-access-ui.js','user-access-ui.js'),('/violation-mail-ui.js','violation-mail-ui.js')]:
        endpoint=next(rule.endpoint for rule in app.url_map.iter_rules() if rule.rule==path)
        app.view_functions[endpoint]=(lambda name=name:Response((ASSETS/name).read_bytes(),content_type='application/javascript; charset=utf-8'))
    @app.get('/api/center/users')
    def center_users():
        denied=actor_guard()
        if denied:return denied
        try:return jsonify(users=inventory(backend),source='S-UI',checked_at=int(time.time()))
        except Exception:return jsonify(error='user_inventory_unavailable'),503
    @app.get('/api/center/nodes')
    def center_nodes():
        denied=actor_guard()
        return denied or jsonify(node_report())
    @app.post('/api/center/nodes/refresh')
    def center_refresh_nodes():
        denied=mutation_guard()
        if denied:return denied
        if int(time.time())-int(node_report().get('checked_at') or 0)<30:return jsonify(state='recent',message='刚完成核查，无需重复执行')
        result=subprocess.run(['systemctl','start','--no-block','security-center-node-audit.service'],capture_output=True,timeout=5)
        return (jsonify(state='queued'),202) if result.returncode==0 else (jsonify(error='node_audit_start_failed'),503)
    def mail(path):
        from violation_mail_plugin import worker_get
        return worker_get(path,18112)
    @app.get('/api/center/events')
    def center_events():
        denied=actor_guard()
        if denied:return denied
        try:return jsonify(mail('events'))
        except Exception:return jsonify(error='confirmed_events_unavailable'),503
    @app.get('/api/center/overview')
    def center_overview():
        denied=actor_guard()
        if denied:return denied
        users=inventory(backend);nodes=node_report()
        try:notification=mail('status')
        except Exception:notification={'available':False,'error':'通知服务暂不可用'}
        operations=[x for x in users if x['state'] not in ('active','revoked') or x.get('error')]
        return jsonify(user_total=len(users),operations=operations,nodes=nodes,notification=notification,checked_at=int(time.time()))
    @app.get('/api/center/audit')
    def center_audit():
        denied=actor_guard()
        if denied:return denied
        try:return jsonify(audit_page(backend,audit))
        except (ValueError,TypeError,KeyError):return jsonify(error='audit_filter_invalid'),400
        except Exception:return jsonify(error='permanent_audit_unavailable'),503
    @app.before_request
    def before_mutation_audit():
        if request.method!='POST' or request.path not in MUTATIONS:return None
        if not admin_request():return None
        from admin_plugin import normalized_origin,public_request_origin
        if normalized_origin(request.headers.get('Origin'))!=public_request_origin() or not same_origin_request():return jsonify(error='same_origin_required'),403
        if request.path=='/api/admin-password' and not verify_view_key():return jsonify(error='second_factor_required'),403
        try:
            event=uuid.uuid4().hex;g.center_audit_event=event
            audit.append(request.authorization.username,MUTATIONS[request.path]+'：已请求',
                details={'request_id':event,'phase':'requested','totp_bound_before':bool(totp_enabled())})
        except Exception:return jsonify(error='permanent_audit_unavailable'),503
    @app.after_request
    def after_center_request(response):
        if request.path.startswith(('/api/center/','/center-assets/')):response.headers['Cache-Control']='no-store'
        event=getattr(g,'center_audit_event',None)
        if event:
            data=response.get_json(silent=True) or {};ok=response.status_code<300 and data.get('ok',True) is not False
            try:audit.append(request.authorization.username,MUTATIONS[request.path]+('：成功' if ok else '：未完成'),
                details={'request_id':event,'phase':'result','http_status':response.status_code,
                    'totp_bound_after':bool(totp_enabled()),'error':str(data.get('error',''))[:80]})
            except Exception:app.logger.error('security_center_permanent_audit_result_unavailable')
        return response
    # Retain the actual, already-committed host-policy deployment in permanent audit.
    path=Path('/root/dmit-host-ingress-20261107/release-proof.json')
    if path.is_file():
        proof=json.loads(path.read_bytes())
        for row in proof.get('peers',[]):
            if row.get('status')=='pass':audit.append('system-deployment','节点入口限源已上线',target=row['peer'],
                event_id='host-policy-'+row['peer']+'-'+row['create_sha256'],
                details={'allowed_sources':row['allowed_sources'],'before':'代理入口限源，管理入口未完全限制',
                    'after':'IPv4与IPv6入站服务仅允许DMIT','verified_at':row['checked_at']})

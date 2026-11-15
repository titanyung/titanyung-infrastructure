/* Navigation and read-only summaries; sensitive actions retain existing backend guards. */
(() => {
  'use strict';
  const root=document.getElementById('security-center-v2');if(!root)return;
  const main=root.querySelector('main'),state=window.SecurityCenter;
  const names={overview:'安全总览',users:'用户与订阅',events:'风险事件',nodes:'节点防护',notifications:'通知中心',audit:'永久操作审计',settings:'后台设置'};
  const intros={overview:'先查看待处理事项，再进入对应页面。',users:'以 S-UI 完整名单为准，分别核对账号、订阅与实际入口状态。',events:'已确认的违规与订阅异常分开查看。',nodes:'核对现役 VPS 的 DMIT 来源限制、IPv4、IPv6 和开机加载。',notifications:'查看违规通知、发送结果和发信配置。',audit:'操作记录只追加、永久保留，独立于访问和流量记录。',settings:'管理统一后台登录与敏感信息访问授权。'};
  const $=id=>document.getElementById(id);
  const make=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;};
  const stamp=value=>{if(!value)return '—';let d=typeof value==='number'?new Date(value*1000):new Date(String(value).replace(' ','T'));return Number.isFinite(d.getTime())?new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Singapore',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(d).replace(/-/g,'.'):String(value);};
  const badge=(text,level='')=>{const e=make('span',text,'sc-status');e.dataset.level=level;return e;};
  const title=main.querySelector('h1');const oldIntro=title.nextElementSibling;if(oldIntro&&oldIntro.classList.contains('muted'))oldIntro.remove();
  const intro=make('p','','sc-page-intro');title.after(intro);
  const oldCards=main.querySelector('.cards');
  const oldPanel=id=>$(id)?.closest('.panel');
  const legacy={password:oldPanel('newAdminPassword'),totp:oldPanel('totpState'),risk:oldPanel('statsRows'),
    subscriptions:oldPanel('subSummaryRows'),access:oldPanel('accessRows'),sensitive:oldPanel('sensitiveOutput')};
  const pages={};for(const key of Object.keys(names)){const section=make('section');section.id='sc-page-'+key;section.className='sc-page';section.dataset.page=key;section.hidden=true;main.append(section);pages[key]=section;}
  function panel(page,id,heading){const e=make('section',undefined,'panel');if(id)e.id=id;if(heading)e.append(make('h2',heading));pages[page].append(e);return e;}
  function jump(page,label,user=''){const e=make('a',label,'sc-jump');e.href='#/'+page+(user?'?user='+encodeURIComponent(user):'');return e;}
  const overview=panel('overview','sc-overview-content');overview.innerHTML='<div id="sc-kpis" class="sc-kpis"></div><h2>需要处理</h2><ul id="sc-attention" class="sc-list"></ul><p id="sc-overview-time" class="sc-note"></p>';
  const userBox=panel('users','sc-users-inventory','用户清单');userBox.innerHTML='<div class="sc-toolbar"><label class="sc-wide">查找用户<input id="sc-user-search" placeholder="用户名或备注"></label><label>账号状态<select id="sc-user-status"><option value="all">全部用户</option><option value="enabled">S-UI 启用</option><option value="disabled">S-UI 禁用</option><option value="controlled">有停用或恢复记录</option></select></label><button id="sc-users-refresh" type="button">刷新名单</button></div><p id="sc-user-total" class="sc-note"></p><div class="table-wrap"><table id="sc-user-table"><thead><tr><th>用户</th><th>S-UI 账号</th><th>订阅</th><th>实际入口</th><th>操作</th></tr></thead><tbody id="sc-user-rows"></tbody></table></div>';
  const selected=panel('users','sc-user-selected');selected.hidden=true;
  const controlSlot=make('div');controlSlot.id='sc-users-controls';pages.users.append(controlSlot);
  if(legacy.subscriptions){pages.users.append(legacy.subscriptions);legacy.subscriptions.hidden=true;legacy.subscriptions.querySelector('h2').textContent='订阅更新记录';}
  if(legacy.sensitive){
    const fileActions=$('fileSelect').closest('.actions');const fileBox=panel('settings','sc-file-controls','敏感配置文件');fileBox.append(make('p','查看前需要当前二次验证，内容不在普通列表显示。','sc-note'),fileActions);
    const result=make('pre');result.id='sc-config-file-output';fileBox.append(result);
    const details=document.createElement('details');details.id='sc-user-sensitive';details.append(make('summary','查看该用户的订阅、节点与二维码（需要二次验证）'));details.append(legacy.sensitive);pages.users.append(details);details.hidden=true;
    legacy.sensitive.querySelector('h2').textContent='订阅与节点信息';
  }
  if(legacy.password)pages.settings.append(legacy.password);if(legacy.totp)pages.settings.append(legacy.totp);
  if(legacy.access){legacy.access.hidden=true;main.append(legacy.access);}
  const confirmed=panel('events','sc-confirmed-events','已确认违规');confirmed.innerHTML='<p class="sc-note">只列已确认的违规证据；订阅请求较多不会直接判为违规。</p><ul id="sc-event-list" class="sc-list"></ul>';
  if(oldCards)pages.events.append(oldCards);
  if(legacy.risk){pages.events.append(legacy.risk);legacy.risk.querySelector('h2').textContent='订阅异常提示';}
  const traffic=panel('events',null,'访问与流量查询');traffic.append(make('p','普通访问明细统一在“流量与访问”查询。','sc-note'));const trafficLink=make('a','进入流量与访问','sc-jump');trafficLink.href='/';traffic.append(trafficLink);
  const nodes=panel('nodes','sc-node-panel');nodes.innerHTML='<div class="sc-toolbar"><button id="sc-node-refresh" type="button">重新核查</button><span id="sc-node-time" class="sc-note"></span></div><p id="sc-node-message" class="sc-note"></p><div id="sc-node-grid" class="sc-node-grid"></div>';
  const notifications=make('div');notifications.id='sc-notification-content';pages.notifications.append(notifications);
  const audit=panel('audit','sc-permanent-audit');audit.innerHTML='<div class="sc-toolbar"><label>用户<input id="sc-audit-user" placeholder="留空查看全部"></label><label>记录类型<select id="sc-audit-category"><option value="all">全部记录</option><option value="business">业务操作与系统部署</option><option value="acceptance">验收测试记录</option></select></label><button id="sc-audit-refresh" type="button">查询</button></div><p class="sc-note">按新加坡时间倒序显示。停用、恢复及设置修改均永久保留。</p><ul id="sc-audit-list" class="sc-list"></ul><button id="sc-audit-more" type="button" hidden>继续读取</button>';
  const actorLabel=make('label','操作来源');actorLabel.insertAdjacentHTML('beforeend','<select id="sc-audit-actor"><option value="all">全部来源</option><option value="manual">人工操作</option><option value="automatic">系统与自动处理</option></select>');$('sc-audit-refresh').before(actorLabel);
  const accountTable=$('sc-user-table');accountTable.querySelector('thead th:last-child').before(make('th','DMIT / Lazycat SG'));
  let users=[],cursor=null,loadingUsers=false,loadingAudit=false,refreshing=false,syncingUser=false;
  let lazycatRows=new Map(),lazycatError='',loadingLazycat=false,lastLazycatRead=0;
  async function api(path,options={}){const r=await fetch('./api/'+path,{credentials:'same-origin',cache:'no-store',...options});let v;try{v=await r.json();}catch(_){throw Error('服务暂时无法响应，请稍后刷新。');}if(!r.ok){const e=Error(v.error==='admin_required'?'需要使用管理员账号登录。':v.error==='csrf_required'?'操作会话已过期，请刷新页面。':v.error||'读取失败');e.code=v.error;throw e;}return v;}
  function error(target,e){const box=$(target);if(box){box.textContent=e.message;box.classList.add('sc-error');}}
  const lazycatErrors={master_native_not_converged:'DMIT 正在收敛账号状态，请稍后下发',master_native_missing:'等待 DMIT 协调器载入账号',lazycat_status_not_checked:'尚未取得实际载入状态',lazycat_operation_unavailable:'暂时无法核查 Lazycat SG',master_authority_superseded:'DMIT 状态已改变，请按当前状态重新下发',master_identity_binding_changed:'账号身份已改变，请刷新名单',lazycat_controller_ack_mismatch:'实际版本与下发记录尚未一致'};
  function lazycatSummary(user){
    const box=make('div',undefined,'sc-lazycat-status'),row=lazycatRows.get(String(user.client_id));
    if(!row){box.append(badge('Lazycat SG：未知','attention'),make('small',lazycatError||'正在读取实际载入状态','sc-note'));return box;}
    box.append(badge('DMIT：'+(row.dmit_state==='enabled'?'启用':'禁用'),row.dmit_state==='enabled'?'good':'attention'));
    box.append(badge('Lazycat SG：'+({loaded:'已载入',missing:'未载入',unknown:'未知'}[row.lazycat_state]||'未知'),row.matches===false?'bad':row.fresh?'good':'attention'));
    if(row.matches===false)box.append(make('small','两端状态不一致','sc-error'));
    box.append(make('small',(row.generation?(row.generation_verified?'已核实版本 ':'上次版本 ')+row.generation+' · ':'')+'最近核对 '+stamp(row.last_checked_at),'sc-note'));
    box.append(make('small','最近成功同步 '+stamp(row.last_sync_at),'sc-note'));
    if(!row.fresh)box.append(make('small','当前载入状态尚未确认','sc-note'));
    if(row.error)box.append(make('small',lazycatErrors[row.error]||'暂未核实完成（'+row.error+'）','sc-error'));
    const job=row.last_request;if(job){box.append(make('small',({queued:'下发请求排队中',running:'正在下发并核验',confirmed:'下发已核实',failed:'下发未完成'}[job.state]||'请求状态待核查')+' · '+stamp(job.updated_at),'sc-note'));if(job.error_code)box.append(make('small',lazycatErrors[job.error_code]||job.error_code,'sc-error'));}
    return box;
  }
  function lazycatButton(user){const button=make('button','下发当前状态');button.type='button';const row=lazycatRows.get(String(user.client_id));button.disabled=!row||!row.can_sync||['queued','running'].includes(row.last_request?.state);button.addEventListener('click',()=>syncLazycat(user,button));return button;}
  function updateSelectedLazycat(){const slot=$('sc-selected-lazycat'),user=users.find(x=>x.username===state.selectedUser);if(slot&&user){slot.replaceChildren(make('h3','Lazycat SG 账号状态'),lazycatSummary(user),lazycatButton(user),make('p','仅下发 DMIT 当前账号状态；账号的停用与恢复使用下方原有操作。','sc-note'));}}
  async function loadLazycat(){if(loadingLazycat)return;loadingLazycat=true;try{const value=await api('center/lazycat/accounts');lazycatRows=new Map((value.users||[]).map(row=>[String(row.client_id),row]));lazycatError='';}catch(e){lazycatRows=new Map();lazycatError='暂时无法核查 Lazycat SG，请稍后刷新。';}finally{loadingLazycat=false;lastLazycatRead=Date.now();}}
  async function syncLazycat(user,button){button.disabled=true;try{const session=await api('user-access/session');const operation=typeof crypto.randomUUID==='function'?crypto.randomUUID():Array.from(crypto.getRandomValues(new Uint8Array(24)),x=>x.toString(16).padStart(2,'0')).join('');await api('center/lazycat/accounts/sync',{method:'POST',headers:{'Content-Type':'application/json','X-User-Access-CSRF':session.csrf_token},body:JSON.stringify({client_id:String(user.client_id),operation_id:operation})});await loadLazycat();drawUsers();updateSelectedLazycat();}catch(e){button.disabled=false;const slot=button.closest('.sc-lazycat-status')||button.parentElement;slot.append(make('p',lazycatErrors[e.code]||e.message,'sc-error'));}}
  function tableLabels(){root.querySelectorAll('table').forEach(t=>{const labels=Array.from(t.querySelectorAll('thead tr:last-child th')).map(x=>x.textContent.trim());if(!labels.length)return;t.classList.add('sc-card-table');t.querySelectorAll('tbody tr').forEach(row=>Array.from(row.children).forEach((td,i)=>{td.dataset.label=labels[i]||'';}));});}
  let frame=0;const observer=new MutationObserver(()=>{if(!frame)frame=requestAnimationFrame(()=>{frame=0;tableLabels();moveWidgets();});});
  function moveWidgets(){
    const u=$('user-access-panel');if(u){if(u.parentElement!==controlSlot)controlSlot.append(u);for(const h of u.querySelectorAll('.uac-heading'))if(h.textContent.includes('永久操作记录'))h.hidden=true;}
    const mail=$('violation-mail-panel');if(mail&&mail.parentElement!==notifications)notifications.append(mail);
  }
  observer.observe(root,{childList:true,subtree:true});
  function drawUsers(){
    const query=$('sc-user-search').value.trim().toLowerCase(),filter=$('sc-user-status').value;
    const shown=users.filter(x=>(!query||(x.username+' '+x.description).toLowerCase().includes(query))&&(filter==='all'||filter==='enabled'&&x.enabled||filter==='disabled'&&!x.enabled||filter==='controlled'&&x.state!=='active'));
    $('sc-user-total').textContent='S-UI 共 '+users.length+' 位用户 · 当前显示 '+shown.length+' 位';
    $('sc-user-rows').replaceChildren();
    for(const user of shown){const tr=make('tr'),name=make('td');name.append(make('strong',user.username),make('span',user.description,'sc-user-description'));tr.append(name);
      for(const [text,level] of [[user.enabled?'启用':'禁用',user.enabled?'good':'attention'],[user.subscription_state,user.state==='active'?'':'attention'],[user.forwarding_state,user.forwarding_state.includes('仍有')||user.forwarding_state.includes('不一致')?'bad':user.state==='revoked'?'good':'']]){const td=make('td');td.append(badge(text,level));tr.append(td);}
      const sync=make('td');sync.append(lazycatSummary(user));tr.append(sync);
      const action=make('td'),button=make('button','查看 / 操作');button.type='button';button.addEventListener('click',()=>chooseUser(user.username,true));action.append(button,lazycatButton(user));action.className='sc-user-actions';tr.append(action);$('sc-user-rows').append(tr);
    }
    if(!shown.length){const tr=make('tr'),td=make('td','没有符合条件的用户。');td.colSpan=6;tr.append(td);$('sc-user-rows').append(tr);}tableLabels();
  }
  async function loadUsers(){if(loadingUsers)return;loadingUsers=true;try{const [value]=await Promise.all([api('center/users'),loadLazycat()]);users=value.users||[];drawUsers();if(state.selectedUser)chooseUser(state.selectedUser,false);}catch(e){error('sc-user-total',e);}finally{loadingUsers=false;}}
  function chooseUser(name,scroll){
    const user=users.find(x=>x.username===name);if(!user)return;state.selectedUser=name;
    if(typeof state.refreshOperations==='function')state.refreshOperations();
    if(scroll&&state.page!=='users')location.hash='#/users?user='+encodeURIComponent(name);
    selected.hidden=false;selected.replaceChildren();selected.append(make('h2',user.username),make('p',user.description,'sc-note'));
    const badges=make('div',undefined,'sc-toolbar');badges.append(badge('S-UI '+(user.enabled?'启用':'禁用')),badge(user.subscription_state),badge(user.forwarding_state));selected.append(badges);
    const links=make('div',undefined,'sc-toolbar');const logs=make('a','在流量页查看访问记录','sc-jump');logs.href='/?user='+encodeURIComponent(name)+'#access';links.append(logs,jump('audit','查看永久操作记录',name));selected.append(links);
    const lazycatSlot=make('section');lazycatSlot.id='sc-selected-lazycat';selected.append(lazycatSlot);updateSelectedLazycat();
    const select=$('uac-user');if(select&&!syncingUser){syncingUser=true;try{select.value=user.client_id;select.dispatchEvent(new Event('change',{bubbles:true}));if($('uac-prepare'))$('uac-prepare').disabled=!user.selectable;}finally{syncingUser=false;}}
    if($('subid'))$('subid').value=name;
    if(legacy.subscriptions){legacy.subscriptions.hidden=false;if(typeof loadSubscriptionSummary==='function')loadSubscriptionSummary().then(()=>{for(const row of $('subSummaryRows').children){row.hidden=row.firstElementChild?.textContent.trim()!==name;}}).catch(()=>{});}
    if($('sc-user-sensitive'))$('sc-user-sensitive').hidden=false;
    if(scroll){history.replaceState(null,'','#/users?user='+encodeURIComponent(name));selected.scrollIntoView({behavior:'smooth',block:'start'});}
  }
  const stateNames={active:'正常',armed:'等待用户下次更新',purge_issued:'已触发停用配置',revoking:'撤销访问中',revoked:'已撤销并验证',restoring:'正在恢复验证',restore_pending:'等待恢复'};
  async function loadOverview(){try{const data=await api('center/overview');const peers=data.nodes.peers||[],good=peers.filter(x=>x.status==='protected').length;const mail=data.notification||{};
    const values=[['节点防护',peers.length?good+' / '+peers.length:'待核查','查看实际规则与开机加载','nodes'],['处理中',data.operations.length,'查看停用、恢复执行结果','users'],['用户清单',data.user_total,'包含 S-UI 禁用用户','users'],['邮件通知',mail.available===false?'服务异常':mail.configured===false?'未配置':'查看状态','队列与发送结果','notifications']];
    $('sc-kpis').replaceChildren();for(const [label,value,note,page] of values){const item=make('div',undefined,'sc-kpi'),button=make('button');button.type='button';button.append(make('span',label),make('strong',value),make('span',note));button.addEventListener('click',()=>{location.hash='#/'+page;});item.append(button);$('sc-kpis').append(item);}
    const list=$('sc-attention');list.replaceChildren();for(const row of data.operations){const li=make('li');li.append(jump('users',row.username,row.username),make('small',stateNames[row.state]||row.state));if(row.error)li.append(make('small','执行尚未确认完成，请查看任务状态。'));list.append(li);}
    for(const row of peers.filter(x=>x.status!=='protected')){const li=make('li');li.append(jump('nodes',row.name+'：防护状态需要核查'));list.append(li);}
    const queue=mail.counts||{};if(mail.available===false||!mail.configured||queue.retry||queue.pending_config){const li=make('li');li.append(jump('notifications',mail.available===false?'通知服务暂不可用':!mail.configured?'发信邮箱尚未配置 · '+(queue.pending_config||0)+' 条通知待配置':'邮件通知有等待重试的记录'));list.append(li);}
    if(!list.children.length)list.append(make('li','当前没有待处理的停用任务、通知异常或节点防护缺口。'));
    $('sc-overview-time').textContent='最近读取 '+stamp(data.checked_at)+' · 以各页面实际核查结果为准';
  }catch(e){error('sc-attention',e);}}
  async function loadNodes(){try{const value=await api('center/nodes');$('sc-node-time').textContent='最近核查 '+stamp(value.checked_at);$('sc-node-message').textContent=value.stale?'核查结果已过期或尚未取得，请重新核查。':'现役 VPS；规则和开机加载均按实机读取。';const grid=$('sc-node-grid');grid.replaceChildren();
    for(const row of value.peers||[]){const card=make('article',undefined,'sc-node'),head=make('div',undefined,'sc-list-head');head.append(make('strong',row.name),badge(row.status==='protected'?'已限制为 DMIT':row.status==='stale'?'结果已过期':'需要核查',row.status==='protected'?'good':'attention'));card.append(head);const dl=make('dl');
      for(const [label,text] of [['保护范围',row.scope],['DMIT IPv4',row.allowed_ipv4],['DMIT IPv6',row.allowed_ipv6],['IPv4 规则',row.ipv4?'已核对':'未确认'],['IPv6 规则',row.ipv6?'已核对':'未确认'],['开机加载',row.persistent?'已启用并验证':'未确认'],['核查时间',stamp(row.verified_at)]])dl.append(make('dt',label),make('dd',text));card.append(dl);grid.append(card);}
  }catch(e){error('sc-node-message',e);}}
  async function refreshNodes(){if(refreshing)return;refreshing=true;$('sc-node-refresh').disabled=true;try{const session=await api('user-access/session');const r=await api('center/nodes/refresh',{method:'POST',headers:{'Content-Type':'application/json','X-User-Access-CSRF':session.csrf_token},body:'{}'});$('sc-node-message').textContent=r.state==='recent'?'刚完成核查，已读取最新结果。':'只读核查已启动，完成后会更新结果。';setTimeout(loadNodes,7000);}catch(e){error('sc-node-message',e);}finally{refreshing=false;$('sc-node-refresh').disabled=false;}}
  async function loadEvents(){try{const value=await api('center/events');const rows=value.events||value.records||[];const list=$('sc-event-list');list.replaceChildren();for(const row of rows){if(row.kind!=='bt-block'||row.eligible===0)continue;const li=make('li'),user=row.user||row.username||row.subid||'未识别用户';li.append(make('strong','BT 违规已阻断'),document.createTextNode(' · '),jump('users',user,user),make('small',stamp(row.ts||row.occurred_at||row.event_time||row.created_at||row.at)));
      let detail={};try{detail=typeof row.detail==='string'?JSON.parse(row.detail):row.detail||{};}catch(_){}
      li.append(make('small','检测来源 '+(row.source||row.source_id||'—')));
      for(const [label,key] of [['匹配规则','rule'],['处理结果','action'],['目标','destination'],['证据','evidence'],['连接编号','connection_id']])if(detail[key])li.append(make('small',label+'：'+detail[key]));
      const notices={pending_config:'通知待配置',queued:'通知排队中',retry:'通知等待重试',sending:'通知发送中',sent:'已发出通知'};li.append(make('small',notices[row.state]||'通知状态待核查'),jump('audit','查看该用户的处理记录',user));list.append(li);}if(!list.children.length)list.append(make('li','近期没有已确认的违规事件。'));}catch(e){error('sc-event-list',e);}}
  const auditActions={armed:'确认停用计划',arm_reaffirmed:'再次确认停用',purge_claimed:'已登记首次停用配置交付',delivery_succeeded:'首次停用配置已发送',delivery_failed:'首次停用配置交付失败',disabled_subscription_issued:'已登记停用配置交付',disabled_delivery_succeeded:'停用配置已发送',disabled_delivery_failed:'停用配置发送失败',revocation_started:'开始撤销访问',revocation_retry_scheduled:'撤销访问等待重试',revoked:'已撤销访问并验证',restore_requested:'确认恢复访问',restored_before_purge:'已取消尚未触发的停用计划',restore_reaffirmed:'再次确认恢复',restore_noop:'已确认无需恢复',restoration_started:'开始恢复并验证',restoration_retry_scheduled:'恢复访问等待重试',restored:'访问已恢复并验证'};
  async function loadAudit(reset=false){if(loadingAudit)return;loadingAudit=true;try{if(reset){cursor=null;$('sc-audit-list').replaceChildren();}const query=new URLSearchParams({user:$('sc-audit-user').value.trim(),category:$('sc-audit-category').value,actor_type:$('sc-audit-actor').value});if(cursor)query.set('before',JSON.stringify(cursor));const value=await api('center/audit?'+query);for(const row of value.events){const li=make('li'),head=make('div',undefined,'sc-list-head');head.append(make('strong',auditActions[row.action]||row.action),make('span',stamp(row.at),'sc-note'));li.append(head,make('small','操作人 '+row.actor+(row.username?' · 对象 '+row.username:'')));const detail=row.details||{};if(detail.reason)li.append(make('p',detail.reason));if(detail.before||detail.after)li.append(make('p',(detail.before||'')+' → '+(detail.after||'')));if(detail.phase)li.append(make('small',detail.phase==='requested'?'请求已登记':'执行结果已登记'));$('sc-audit-list').append(li);}cursor=value.next_before;$('sc-audit-more').hidden=!value.has_more;if(!$('sc-audit-list').children.length)$('sc-audit-list').append(make('li','没有符合条件的操作记录。'));}catch(e){error('sc-audit-list',e);}finally{loadingAudit=false;}}
  function route(){const raw=location.hash.replace(/^#\//,'').split('?');const key=Object.hasOwn(names,raw[0])?raw[0]:'overview';state.page=key;const query=new URLSearchParams(raw[1]||'');for(const name of Object.keys(pages))pages[name].hidden=name!==key;title.textContent=names[key];intro.textContent=intros[key];$('sc-page-picker').value=key;root.dataset.page=key;root.querySelectorAll('[data-sc-nav]').forEach(a=>{if(a.dataset.scNav===key)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');});
    try{sessionStorage.setItem('security-center-page',key);}catch(_){}
    if(key!=='users'){$('sensitiveOutput').textContent='敏感内容将在这里显示';$('qr').replaceChildren();if($('sc-user-sensitive'))$('sc-user-sensitive').open=false;}if(key!=='settings')$('sc-config-file-output').textContent='';
    if(key==='overview')loadOverview();if(key==='users'){if(query.has('user'))state.selectedUser=query.get('user');loadUsers();}if(key==='events'){loadEvents();if(typeof loadStats==='function')loadStats().catch(()=>{});}if(key==='nodes')loadNodes();if(key==='audit'){if(query.has('user'))$('sc-audit-user').value=query.get('user');loadAudit(true);}window.dispatchEvent(new CustomEvent('security:center:page',{detail:{page:key}}));tableLabels();moveWidgets();
  }
  $('sc-page-picker').addEventListener('change',e=>{location.hash='#/'+e.target.value;});window.addEventListener('hashchange',route);
  for(const id of ['sc-user-search','sc-user-status','sc-audit-user','sc-audit-category','sc-audit-actor']){const input=$(id);try{const value=sessionStorage.getItem('security-center-'+id);if(value!==null)input.value=value;}catch(_){}input.addEventListener('input',()=>{try{sessionStorage.setItem('security-center-'+id,input.value);}catch(_){}});input.addEventListener('change',()=>{try{sessionStorage.setItem('security-center-'+id,input.value);}catch(_){}});}
  root.addEventListener('change',event=>{if(event.target.id!=='uac-user'||syncingUser)return;const user=users.find(x=>String(x.client_id)===event.target.value);if(user)chooseUser(user.username,false);});
  window.addEventListener('security:center:users-updated',()=>{if(state.page==='users')loadUsers();});
  $('sc-user-search').addEventListener('input',drawUsers);$('sc-user-status').addEventListener('change',drawUsers);$('sc-users-refresh').addEventListener('click',loadUsers);$('sc-node-refresh').addEventListener('click',refreshNodes);$('sc-audit-refresh').addEventListener('click',()=>loadAudit(true));$('sc-audit-more').addEventListener('click',()=>loadAudit(false));
  if(!location.hash){let saved='';try{saved=sessionStorage.getItem('security-center-page')||'';}catch(_){}if(Object.hasOwn(names,saved)){history.replaceState(null,'','#/'+saved);}}
  route();setInterval(()=>{if(document.hidden)return;if(state.page==='overview')loadOverview();if(state.page==='nodes')loadNodes();},30000);
  setInterval(async()=>{if(document.hidden||state.page!=='users'||loadingLazycat||loadingUsers)return;if(Date.now()-lastLazycatRead>=30000||Array.from(lazycatRows.values()).some(row=>['queued','running'].includes(row.last_request?.state))){await loadLazycat();drawUsers();updateSelectedLazycat();}},5000);
})();

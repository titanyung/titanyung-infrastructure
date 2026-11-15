/* Uses the security page's existing administrator and second-factor checks. */
(() => {
  'use strict';
  const main=document.querySelector('main');
  if(!main||document.getElementById('user-access-panel'))return;
  const panel=document.createElement('section');panel.className='panel';panel.id='user-access-panel';
  panel.innerHTML=`<h2>👤 用户访问控制</h2>
    <p class="muted">人工封禁期间，每台设备每次更新均下发“账号已停用”配置，机场节点保持为空；首次主订阅更新后撤销代理访问。恢复后正常下发订阅；操作及交付记录永久保留。</p>
    <div id="uac-result" class="uac-result" role="status" aria-live="polite"></div>
    <form id="uac-form" autocomplete="off">
      <div class="uac-form-grid"><label>选择用户<select id="uac-user" required><option value="">正在读取用户</option></select></label>
      <label>操作原因（可选）<input id="uac-reason" type="text" maxlength="500" placeholder="填写本次停用原因"></label></div>
      <p id="uac-user-summary" class="muted" aria-live="polite">正在核对 S-UI 用户名单</p>
      <div class="uac-actions"><button id="uac-prepare" type="submit" disabled>查看并确认停用方案</button><button id="uac-refresh" type="button">刷新状态</button></div>
    </form>
    <section id="uac-review" class="uac-review" aria-labelledby="uac-review-title" tabindex="-1" hidden>
      <h3 id="uac-review-title"></h3><ol id="uac-consequences"></ol>
      <p id="uac-expiry" class="muted"></p><label class="uac-ack"><input id="uac-ack" type="checkbox"><span id="uac-ack-text"></span></label>
      <div class="uac-actions"><button id="uac-confirm" type="button" class="uac-danger" disabled>确认，等待用户下次更新</button><button id="uac-cancel" type="button">返回修改</button></div>
    </section>
    <div class="uac-heading"><h3>执行状态</h3><span class="muted">以服务端确认结果为准</span></div><ul id="uac-operations" class="uac-list"></ul>
    <div class="uac-heading"><h3>永久操作记录</h3><span class="muted">按时间顺序排列，不随流量记录清理</span></div>
    <ol id="uac-audit" class="uac-list"></ol><button id="uac-more" type="button" hidden>继续读取记录</button>`;
  main.prepend(panel);
  const $=id=>panel.querySelector('#uac-'+id);
  const make=(tag,cls,text)=>{const node=document.createElement(tag);if(cls)node.className=cls;if(text!==undefined)node.textContent=String(text);return node;};
  const states={active:'正常',armed:'等待下次订阅更新',purge_issued:'已触发订阅清理',revoking:'正在停用代理访问',revoked:'已停用',restore_pending:'等待恢复访问',restoring:'正在恢复并验证访问',disabled:'S-UI 已禁用',unconfigured:'尚未配置有效入口',trial:'测试账号，独立策略',identity_conflict:'账号信息已变更',unavailable:'暂不可操作'};
  const actions={armed:'停用计划已确认',arm_reaffirmed:'停用计划再次确认',purge_claimed:'首次禁用配置交付已登记',delivery_succeeded:'首次禁用配置响应已发送',delivery_failed:'首次禁用配置响应发送失败',disabled_subscription_issued:'禁用配置交付已登记',disabled_delivery_succeeded:'禁用配置响应已发送',disabled_delivery_failed:'禁用配置响应发送失败',revocation_started:'开始停用代理访问',revocation_retry_scheduled:'已安排停用重试',revoked:'代理访问已停用',restore_requested:'恢复访问已确认',restored_before_purge:'已取消未执行的停用计划',restore_reaffirmed:'已再次确认恢复访问',restore_noop:'已确认用户无需恢复',restoration_started:'开始恢复访问',restoration_retry_scheduled:'已安排恢复重试',restored:'访问已恢复并验证'};
  const errors={admin_required:'需要管理员身份。',session_required:'操作会话已过期，请刷新后重新确认。',same_origin_required:'请从统一后台打开本页面后操作。',csrf_required:'页面验证已失效，请刷新后重试。',recent_auth_required:'请重新验证管理员身份。',second_factor_required:'动态码或查看密钥不正确。',target_not_eligible:'该用户已变更或不再符合操作条件，请刷新列表。',operation_already_exists:'该用户已有停用计划，请查看执行状态。',restore_not_available:'该用户当前无需恢复，或已有恢复任务，请刷新状态。',operation_conflict:'用户或计划状态已变更，请刷新查看。',confirmation_expired:'确认已过期，请重新查看操作方案。',confirmation_invalid:'确认信息已失效，请重新查看操作方案。',confirmation_binding_changed:'目标用户或操作会话已变更，请重新确认。',confirmation_acknowledgement_required:'请先核对并勾选确认目标用户。',access_control_temporarily_unavailable:'访问控制服务暂不可用，请稍后刷新。'};
  const stamp=value=>Number.isFinite(Number(value))&&Number(value)>0?new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Kuala_Lumpur',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(new Date(Number(value)*1000)).replace(/-/g,'.'):'—';
  let csrf='',mode='totp',pending=null,busy=false,after=0;
  function message(text,error=false){$('result').textContent=text;$('result').dataset.error=String(error);}
  async function request(path,{method='GET',body,headers={}}={}){
    const response=await fetch('./api/user-access/'+path,{method,credentials:'same-origin',cache:'no-store',
      headers:{...headers,...(method==='POST'?{'Content-Type':'application/json','X-User-Access-CSRF':csrf}:{})},
      body:body===undefined?undefined:JSON.stringify(body)});
    let payload;try{payload=await response.json();}catch(_){throw Error('服务暂时无法响应，请稍后刷新。');}
    if(!response.ok){const error=Error(errors[payload.error]||'操作未完成，请刷新后重试。');error.code=payload.error;throw error;}
    return payload;
  }
  async function session(){const value=await request('session');csrf=value.csrf_token;mode=value.auth_mode;}
  async function reauthenticate(){
    const key=typeof askKey==='function'?askKey():prompt(mode==='totp'?'请输入现有的6位动态码':'请输入现有的敏感信息查看密钥');
    if(!key)return false;
    await request('reauth',{method:'POST',body:{},headers:{[mode==='totp'?'X-TOTP-Code':'X-View-Key']:key}});
    return true;
  }
  async function protectedPost(path,body){
    try{return await request(path,{method:'POST',body});}
    catch(error){if(error.code==='recent_auth_required'&&await reauthenticate())return request(path,{method:'POST',body});throw error;}
  }
  function closeReview(){pending=null;$('review').hidden=true;$('ack').checked=false;$('confirm').disabled=true;}
  function drawOperations(rows){
    $('operations').replaceChildren();
    for(const row of Array.isArray(rows)?rows:[]){
      const item=make('li','uac-card'),head=make('div','uac-card-head');
      head.append(make('strong','',row.username),make('span','uac-state',states[row.state]||'状态正在确认'));item.append(head);
      item.append(make('p','muted','更新时间 '+stamp(row.updated_at)));
      if(row.delivery_state==='failed')item.append(make('p','uac-warning','清理订阅响应未成功发送，请关注后续停用状态。'));
      if(row.last_error_code)item.append(make('p','uac-warning','执行正在重试，尚未确认完成。'));
      if(['armed','purge_issued','revoking','revoked'].includes(row.state)){
        const restore=make('button','uac-restore',row.state==='armed'?'取消停用计划':'恢复该用户访问');restore.type='button';
        restore.addEventListener('click',()=>prepare('restore',String(row.client_id)));item.append(restore);
      }
      $('operations').append(item);
    }
    if(!$('operations').children.length)$('operations').append(make('li','muted','暂无停用计划。'));
  }
  function drawUsers(rows){
    const selected=$('user').value;$('user').replaceChildren(make('option','','请选择要操作的用户'));
    $('user').firstChild.value='';
    const users=Array.isArray(rows)?rows:[];
    for(const row of users){const note=row.selectable?(row.enabled===false?' · S-UI 已禁用，仍可停用代理访问':''):' · '+(states[row.state]||states[row.unavailable_reason]||'暂不可操作');const option=make('option','',row.username+note);option.value=row.client_id;option.disabled=!row.selectable;$('user').append(option);}
    $('user-summary').textContent='已显示 S-UI 全部 '+users.length+' 位用户 · 当前可停用 '+users.filter(row=>row.selectable).length+' 位；其余用户保留显示并注明状态。';
    if(Array.from($('user').options).some(option=>option.value===selected&&!option.disabled))$('user').value=selected;
    $('prepare').disabled=!$('user').value||busy;
  }
  async function overview(){const value=await request('overview');drawUsers(value.users);drawOperations(value.operations);}
  async function audit(reset=false){
    if(reset){after=0;$('audit').replaceChildren();}
    const value=await request('audit?after_sequence='+after);
    for(const row of Array.isArray(value.events)?value.events:[]){
      const item=make('li','uac-card'),head=make('div','uac-card-head');head.append(make('strong','',row.username),make('time','muted',stamp(row.at)));item.append(head);
      item.append(make('p','',actions[row.action]||'操作状态更新'),make('p','muted','操作者 '+(row.actor||'系统')));
      if(row.details&&typeof row.details.reason==='string'&&row.details.reason)item.append(make('p','muted','原因：'+row.details.reason));
      if(row.details&&row.details.superseded===true)item.append(make('p','muted','这是此前封禁操作的交付记录，不影响当前恢复状态。'));
      $('audit').append(item);
    }
    after=Number(value.next_after_sequence)||after;$('more').hidden=!value.has_more;
    if(!$('audit').children.length)$('audit').append(make('li','muted','暂无操作记录。'));
  }
  async function prepare(action,target){
    if(busy||!target)return;busy=true;$('prepare').disabled=true;
    try{const value=await protectedPost('prepare',{client_id:target,reason:$('reason').value,action});
      pending=value;const restoring=value.action==='restore';
      $('review-title').textContent=(restoring?'确认恢复用户：':'确认停用用户：')+value.target.username;
      $('ack-text').textContent='我已核对，本次'+(restoring?'恢复':'停用')+'的用户是 '+value.target.username;
      $('consequences').replaceChildren();
      const consequences=restoring?['尚未触发订阅清理时，取消该用户的停用计划。','已触发清理或停用时，重新配置并验证代理访问；验证完成前保持阻止访问。','恢复过程及结果进入永久操作记录。']:['人工封禁期间，该用户各设备每次更新均只收到“账号已停用”配置；机场节点保持为空。','首次主订阅更新后撤销其代理访问；后续更新不会重复建立或推迟撤权任务。','恢复并验证完成后正常下发订阅；确认、交付原因及结果永久保留。'];
      consequences.forEach(text=>$('consequences').append(make('li','',text)));
      $('confirm').textContent=restoring?'确认恢复该用户访问':'确认，等待用户下次更新';
      $('expiry').textContent='本次确认有效至 '+stamp(value.expires_at)+'；不会立即操作其他用户。';
      $('ack').checked=false;$('confirm').disabled=true;$('review').hidden=false;$('review').focus();message('请核对用户名和操作后果。');
    }catch(error){message(error.message,true);}finally{busy=false;$('prepare').disabled=!$('user').value;}
  }
  $('form').addEventListener('submit',event=>{event.preventDefault();prepare('arm',$('user').value);});
  $('ack').addEventListener('change',()=>{$('confirm').disabled=busy||!$('ack').checked||!pending;});
  $('user').addEventListener('change',()=>{closeReview();$('prepare').disabled=!$('user').value||busy;});
  $('cancel').addEventListener('click',()=>{closeReview();$('user').focus();});
  $('confirm').addEventListener('click',async()=>{
    if(busy||!pending||!$('ack').checked)return;
    if(Date.now()/1000>=pending.expires_at){closeReview();message(errors.confirmation_expired,true);return;}
    busy=true;$('confirm').disabled=true;
    try{const action=pending.action;const value=await protectedPost('confirm',{client_id:pending.target.client_id,confirmation_token:pending.confirmation_token,acknowledged:true,action});
      closeReview();message(action==='restore'?(value.operation.state==='active'?'停用计划已取消，该用户保持正常。':'恢复已确认，正在重新配置并验证访问。请以下方执行状态为准。'):'停用计划已确认，等待该用户下次更新订阅。请以下方执行状态为准。');await overview();await audit(true);
    }catch(error){message(error.message,true);}finally{busy=false;$('confirm').disabled=!pending||!$('ack').checked;}
  });
  $('refresh').addEventListener('click',async()=>{if(busy)return;closeReview();try{await session();await overview();await audit(true);message('状态已刷新。');}catch(error){message(error.message,true);}});
  $('more').addEventListener('click',async()=>{try{await audit();}catch(error){message(error.message,true);}});
  (async()=>{try{await session();await overview();await audit(true);}catch(error){message(error.message,true);}})();
})();

/* Additional current-topology view; original dashboard remains responsible
   for records, filters, server detail controls and authenticated API calls. */
(() => {
  if (typeof drawServers !== 'function' || typeof node !== 'function') return;
  const originalServers = drawServers;
  let archiveOpen = false;
  const relayExits=()=>{
    const topology=data&&data.whole&&data.whole.topology;
    if(topology&&topology.routing_revision==='routing-revision-20261109-v1')
      return(topology.active_hosts||[]).filter(name=>!['DMIT','Lazycat-SG-Front'].includes(name));
    return ['zorocloud','ByteVirt-TW','Lazycat-SG','Lazycat-HKT','Uzuma-SG-Singtel1'].concat(
      topology&&topology.server_policy==='dmit-domain-routing-20261106'?['ByteVirt-HK ISP']:[]);
  };
  const label=(peer,item)=>item&&item.display_name||peer;
  function billing(card,item){
    const info=item&&item.inventory;
    if(!info)return;
    const currency=info.currency==='CNY'?'¥':'US$';
    const cycle=info.period==='year'?'/年 · 每年 '+String(info.month).padStart(2,'0')+'月'+String(info.day).padStart(2,'0')+'日'
      :'/月 · 每月 '+info.day+'日';
    card.append(node('div','relay-caption server-billing',info.network+' · '+currency+info.amount+cycle));
    if(info.quota||info.speed)card.append(node('div','relay-caption',(info.quota||'流量未公布')+' / '+(info.speed||'速率未公布')));
    if(item.monitoring_epoch_started_at)card.append(node('div','relay-caption',
      '本期采样开始 '+dateTime(item.monitoring_epoch_started_at)+' · 此前记录保留在历史阶段'));
  }
  const measured=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0;
  const validObservation=(observation,estimated,peer='zorocloud')=>observation&&observation.observed_on==='DMIT'
    &&['DMIT','confirmed record ingress'].includes(observation.first_hop)&&observation.relay===peer
    &&observation.estimated===estimated&&observation.independent_egress_meter===false
    &&measured(observation.sessions)&&observation.sessions>0
    &&['upload','download','bytes'].every(key=>measured(observation[key]));
  if(typeof relayBreakdown==='function'){
    const originalRelay=relayBreakdown;
    relayBreakdown=function(card,item,name){
      const observations=name==='DMIT'&&item.relay_observations||{};
      // Only this displayed application row changes basis. The source object,
      // service counters, wire column, and every other destination are intact.
      const display={...item,static_outbound:{...(item.static_outbound||{})}};
      for(const peer of relayExits())if(validObservation(observations[peer],false,peer))
        display.static_outbound[peer]=observations[peer].bytes;
      originalRelay(card,display,name);
      if(name!=='DMIT')return;
      for(const peer of relayExits()){
        const row=card.querySelector('[data-provider="'+peer+'"]');
        if(!row)continue;
        const observation=observations[peer],confirmed=validObservation(observation,false,peer);
        const provider=row.querySelector('.relay-provider'),kind=row.querySelector('.relay-provider-kind');
        if(kind)kind.textContent=confirmed?'中转 · 近 30 天应用量':'中转 · 当前服务计数';
        if(confirmed){
          row.dataset.basis='confirmed_forwarding_application';
          const prior=row.querySelector('.zoro-observed-at');if(prior)prior.remove();
          if(provider&&measured(observation.last_observed_at)&&observation.last_observed_at>0)
            provider.append(node('span','relay-provider-kind zoro-observed-at','观测 '+dateTime(observation.last_observed_at)));
        }
      }
    };
  }
  function zoroApplication(card,item,peer='zorocloud') {
    const section=node('section','relay-breakdown zoro-route','');
    section.append(node('h4','','DMIT → '+label(peer,item)));
    const observation=item.application_observation;
    const valid=validObservation(observation,true,peer);
    if(!valid){
      section.append(node('div','relay-caption',item.application_observation_state==='no_confirmed_sessions_in_window'
        ?'本统计周期暂无已确认的中转连接。':'中转应用量暂不可用。'));
      card.append(section);return;
    }
    section.dataset.observedOn='DMIT';section.dataset.estimated='true';
    section.append(node('div','relay-caption','应用流量估算 · 近 30 天'));
    const metrics=node('div','relay-caption','');
    for(const [label,key] of [['用户上传','upload'],['用户下载','download'],['应用流量合计','bytes']]){
      const row=node('div','direct-stat','');row.dataset.stat='zoro-'+key;
      row.append(node('span','',label),node('strong','',fmt(observation[key])));metrics.append(row);
    }
    section.append(metrics);
    const count=observation.sessions.toLocaleString('zh-CN')+' 条连接'
      +(measured(observation.users)?' · '+observation.users.toLocaleString('zh-CN')+' 位用户':'');
    section.append(node('div','relay-caption',count));
    section.append(node('div','relay-caption','最近观测 '+(measured(observation.last_observed_at)
      &&observation.last_observed_at>0?dateTime(observation.last_observed_at):'时间暂不可用')));
    if(measured(observation.window_start)&&measured(observation.window_end))section.title=
      '统计范围 '+dateTime(observation.window_start)+' — '+dateTime(observation.window_end);
    section.append(node('div','relay-caption','来自已确认入口的转发观测，应用量估算；不与上方网卡计数相加。'));
    card.append(section);
  }
  function zoroCard(item,peer='zorocloud') {
    const card=node('section','server-card',''),title=node('div','server-title','');
    card.dataset.topologyZoro='true';
    card.dataset.serverKey=peer;
    const fresh=item.sampled_at&&Date.now()/1000-item.sampled_at<180;
    title.append(node('h3','',label(peer,item)),node('span',fresh?'ok':'off',
      item.sampled_at?'最后采样 '+dateTime(item.sampled_at):'等待首个实测样本'));
    card.append(title);
    billing(card,item);
    const bytes=node('div','bytes','');
    for(const [label,value] of [['进站',item.in],['出站',item.out]]){
      const metric=node('div','metric','');
      metric.append(node('span','',label+' · 近 30 天'),node('strong','',measured(value)?fmt(value):'尚未采集'));
      bytes.append(metric);
    }
    card.append(bytes);
    if(!item.sampled_at)card.append(node('div','muted','尚无整机实测样本。服务商套餐额度及初始用量不作为网卡采样。'));
    const exit=item.exit_observation;
    if(exit&&typeof exit.ip==='string'&&measured(exit.observed_at)&&exit.observed_at>0)
      card.append(node('div','relay-caption','最近实测出口 '+exit.ip+' · '+dateTime(exit.observed_at)+'（动态地址）'));
    if(relayExits().includes(peer))zoroApplication(card,item,peer);
    return card;
  }
  drawServers=function(){
    originalServers();
    const whole=data&&data.whole,topology=whole&&whole.topology;
    for(const card of Array.from($('servers').children)){
      const title=card.querySelector('.server-title h3');
      if(!title)continue;
      const key=card.dataset.serverKey||title.textContent,item=whole&&whole.servers&&whole.servers[key];
      card.dataset.serverKey=key;
      if(item&&item.display_name)title.textContent=item.display_name;
      if(item&&!item.sampled_at&&!item.last_measured_at)
        for(const amount of card.querySelectorAll('.bytes .metric strong'))amount.textContent='尚未采集';
      if(item&&!relayExits().includes(key))billing(card,item);
    }
    // The maintained original page may already create a generic Zoro card.
    // Always replace it so refreshes cannot retain the old empty path panel.
    for(const peer of relayExits())if(whole&&whole.servers&&whole.servers[peer]){
      const existing=Array.from($('servers').children).filter(card=>{
        const title=card.querySelector('.server-title h3');return card.dataset.serverKey===peer||title&&title.textContent===peer;
      });
      const replacement=zoroCard(whole.servers[peer],peer);
      if(existing.length){existing[0].replaceWith(replacement);for(const duplicate of existing.slice(1))duplicate.remove();}
      else $('servers').append(replacement);
      const choice=document.getElementById('usage-server');
      if(choice&&!Array.from(choice.options).some(option=>option.value===peer)){
        const option=node('option','',label(peer,whole.servers[peer]));option.value=peer;choice.append(option);
      }
      const relayChoice=document.getElementById('relay');
      if(relayChoice&&!Array.from(relayChoice.options).some(option=>option.value===peer)){
        const option=node('option','',label(peer,whole.servers[peer]));option.value=peer;relayChoice.append(option);
      }
    }
    for(const peer of topology&&topology.active_hosts||[]){
      if(!whole||!whole.servers||!whole.servers[peer])continue;
      if(!Array.from($('servers').children).some(card=>card.dataset.serverKey===peer))
        $('servers').append(zoroCard(whole.servers[peer],peer));
    }
    if(!topology)return;
    const snapshotId='topology-snapshot-note';
    let snapshot=document.getElementById(snapshotId);
    if(data.bootstrap_saved_at){
      if(!snapshot){snapshot=node('div','muted','');snapshot.id=snapshotId;$('servers').before(snapshot);}
      snapshot.textContent='切换前访问快照 · 保存于 '+dateTime(data.bootstrap_saved_at)+'；服务器采样已刷新，访问汇总正在后台更新。';
    }else if(snapshot)snapshot.remove();
    let panel=document.getElementById('topology-archive-panel');
    if(!panel){
      panel=node('details','panel','');panel.id='topology-archive-panel';
      panel.append(node('summary','','归档服务器'),node('div','server-grid',''));
      panel.lastChild.id='topology-archive-grid';
      panel.addEventListener('toggle',()=>archiveOpen=panel.open);
      $('servers').after(panel);
    }
    const archives=document.getElementById('topology-archive-grid');archives.textContent='';
    for(const card of Array.from($('servers').children)){
      const title=card.querySelector('.server-title h3');
      if(title&&(topology.archived_hosts||[]).includes(card.dataset.serverKey||title.textContent)){
        card.dataset.archived='true';archives.append(card);
      }
    }
    for(const [peer,epochs] of Object.entries(topology.historical_monitoring_epochs||{})){
      for(const epoch of epochs){
        const item=epoch.card||{},card=node('section','server-card',''),title=node('div','server-title','');
        card.dataset.archived='true';
        title.append(node('h3','',label(peer,whole.servers[peer])+' · 历史阶段'),
          node('span','off','采样截止 '+dateTime(item.freeze_at||epoch.closed_at)));
        card.append(title);
        const bytes=node('div','bytes','');
        for(const [name,value] of [['进站',item.in],['出站',item.out]]){
          const metric=node('div','metric','');metric.append(node('span','',name),node('strong','',fmt(value)));bytes.append(metric);
        }
        card.append(bytes,node('div','relay-caption','真实最后采样 '+dateTime(item.last_measured_at||item.sampled_at)));
        if((epoch.users||[]).length){
          const users=node('details','', '');users.append(node('summary','','历史用户用量 · '+epoch.users.length+' 人'));
          for(const row of epoch.users)users.append(node('div','split-row',row.user+' · '+fmt(row.total)));
          card.append(users);
        }
        archives.append(card);
      }
    }
    panel.hidden=!archives.children.length;panel.open=archiveOpen;
    panel.firstChild.textContent='归档服务器与历史阶段 · '+archives.children.length+' 项（历史保留）';
    for(const peer of topology.active_hosts||[]){
      const card=Array.from($('servers').children).find(item=>item.dataset.serverKey===peer);
      if(card)$('servers').append(card);
    }
    for(const id of ['usage-server','relay']){
      const choice=document.getElementById(id);
      if(choice)for(const option of Array.from(choice.options)){
        const item=whole.servers&&whole.servers[option.value];
        if(item&&item.display_name)option.textContent=item.display_name;
      }
    }
  };
  const select=document.getElementById('usage-server');
  if(select&&!Array.from(select.options).some(option=>option.value==='zorocloud')){
    const option=node('option','','zorocloud');option.value='zorocloud';select.append(option);
  }
  if(typeof drawUsers==='function'){
    const originalUsers=drawUsers;
    drawUsers=function(){
      originalUsers();
      let usageState=document.getElementById('topology-user-usage-state');
      if(!usageState){usageState=node('div','muted','');usageState.id='topology-user-usage-state';$('users').before(usageState);}
      const pending=data&&data.server_user_usage_state!=='ready';
      const asof=data&&data.server_user_usage_asof;
      usageState.textContent=pending
        ?'用户用量正在完整汇总；当前保留'+(asof?'截至 '+dateTime(asof)+' 的':'')+'已确认数据，尚未显示的用量待确认，不计为 0。'
        :'用户用量已完整更新'+(asof?' · '+dateTime(asof):'');
      usageState.dataset.state=pending?'pending':'ready';
      const selected=select&&select.value;
      if(selected){
        if(relayExits().includes(selected)&&$('users').firstElementChild){
          const card=$('users').firstElementChild,head=card.querySelector('.usage-card-head');
          const title=head&&Array.from(head.children).find(item=>item.tagName==='STRONG');
          if(title)title.textContent=label(selected,data.whole&&data.whole.servers&&data.whole.servers[selected]);
          card.append(node('div','muted','DMIT 转发应用量估算；非独立网卡逐用户采样。'));
        }
        return;
      }
      for(const peer of relayExits()){
        const rows=(data&&data.server_user_usage||[]).filter(row=>row.server===peer);
        if(!rows.length)continue;
        const existing=Array.from($('users').children).find(card=>{
          const head=card.querySelector('.usage-card-head');
          const title=head&&Array.from(head.children).find(item=>item.tagName==='STRONG');
          return title&&title.textContent===peer;
        });
        if(existing){
          const head=existing.querySelector('.usage-card-head'),title=Array.from(head.children).find(item=>item.tagName==='STRONG');
          title.textContent=label(peer,data.whole&&data.whole.servers&&data.whole.servers[peer]);
          existing.append(node('div','muted','DMIT 转发应用量估算；非独立网卡逐用户采样。'));
          continue;
        }
        const card=node('section','usage-card',''),title=node('div','usage-card-head','');
        title.append(node('strong','',label(peer,data.whole&&data.whole.servers&&data.whole.servers[peer])),node('span','',fmt(rows.reduce((sum,row)=>sum+Number(row.total||0),0))));card.append(title);
        card.append(node('div','muted','DMIT 转发应用量估算；非独立网卡逐用户采样。'));
        for(const row of rows)card.append(node('div','split-row',row.user+' · '+fmt(row.total)));
        $('users').append(card);
      }
    };
  }
  function countNote(){
    if(!data||!data.records_rows_asof)return;
    const diagnostic=typeof activeTab!=='undefined'&&activeTab==='observations';
    const note=document.getElementById(diagnostic?'observation-note':'record-note');
    if(note){
      const total=typeof data.records_total==='number'?'共 '+data.records_total.toLocaleString('zh-CN')+' 条':'总数统计中';
      note.textContent=total+' · 第 '+(Number(data.records_page||0)+1)+' 页'+(data.records_count_asof?' · 总数截至 '+dateTime(data.records_count_asof):'')+(data.records_count_pending?'（后台更新中）':'');
    }
    const next=document.getElementById(diagnostic?'obs-next':'next');
    if(next)next.disabled=!data.records_has_more;
  }
  for(const functionName of ['drawRecords','drawObservations']){
    // The maintained page exports these functions as global declarations.
    const original=window[functionName];
    if(typeof original==='function')window[functionName]=function(){const result=original.apply(this,arguments);countNote();return result;};
  }
  countNote();
  if(data){drawServers();if(typeof drawUsers==='function')drawUsers();}
})();

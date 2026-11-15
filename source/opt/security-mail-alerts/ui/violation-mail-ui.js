/* SMTP settings use the security page's existing second-factor verifier. */
(() => {
  'use strict';
  const main = document.querySelector('main');
  if (!main || document.getElementById('violation-mail-panel')) return;
  const panel = document.createElement('section');
  panel.id = 'violation-mail-panel';
  panel.className = 'panel';
  panel.innerHTML = `<h2>📧 违规邮件通知</h2>
    <p class="muted">已确认的用户违规事件通知到 <strong>titan@titanyung.top</strong>。订阅请求次数、来源 IP 异常仍作为风险提示。</p>
    <div class="vm-summary"><strong id="vm-state">正在读取</strong><span id="vm-counts" class="muted"></span></div>
    <div id="vm-result" role="status" aria-live="polite"></div>
    <details class="vm-settings"><summary>配置发信邮箱</summary>
      <p class="muted">可使用飞书邮箱，在邮箱设置的“第三方客户端登录”中生成专用密码，并在此填写。<a class="vm-help" href="https://www.feishu.cn/hc/zh-CN/articles/902478147400" target="_blank" rel="noopener noreferrer">飞书官方操作步骤 ↗</a></p>
      <p class="muted">个人邮箱：在电脑安装的飞书客户端操作，管理员需先允许第三方客户端登录。公共邮箱：管理后台 → 产品设置 → 邮箱 → 地址管理 → 公共邮箱 → 编辑 → 开启 IMAP/SMTP 服务。<a class="vm-help" href="https://www.feishu.cn/hc/zh-CN/articles/221905160046" target="_blank" rel="noopener noreferrer">公共邮箱说明 ↗</a></p>
      <form id="vm-form" autocomplete="off">
        <div class="vm-grid">
          <label>SMTP 服务器<input name="host" value="smtp.feishu.cn" required></label>
          <label>连接方式<select name="mode"><option value="ssl">SSL</option><option value="starttls">STARTTLS</option></select></label>
          <label>端口<input name="port" type="number" value="465" min="1" max="65535" required></label>
          <label>SMTP 用户名<input name="username" type="email" autocomplete="username" value="titan@titanyung.top" required></label>
          <label>发件地址<input name="sender" type="email" value="titan@titanyung.top" required></label>
          <label>专用密码<input name="password" type="password" autocomplete="new-password" placeholder="已保存后留空可保留原密码"></label>
        </div>
        <div class="vm-actions"><button type="submit">验证身份并保存配置</button><button id="vm-test" type="button" disabled>发送测试通知</button></div>
      </form>
      <p class="muted">保存与发送测试通知都需要现有动态码或查看密钥。密码仅保存在服务器受保护配置中，页面不会回显。</p>
    </details>
    <div class="vm-section-head"><h3>违规事件采集</h3><span id="vm-source-note" class="muted">正在读取</span></div>
    <p id="vm-coverage" class="muted"></p><div id="vm-sources" class="vm-sources"></div>
    <div class="vm-section-head"><h3>近期通知</h3><span id="vm-event-note" class="muted">正在读取</span></div>
    <div class="vm-events-wrap"><table class="vm-events"><thead><tr><th>事件时间</th><th>用户</th><th>类型</th><th>通知状态</th><th>已发送时间</th></tr></thead><tbody id="vm-events"><tr><td colspan="5">正在读取通知记录</td></tr></tbody></table></div>`;
  const first = main.querySelector('.panel');
  if (first) main.insertBefore(panel, first); else main.append(panel);
  const state = panel.querySelector('#vm-state');
  const counts = panel.querySelector('#vm-counts');
  const result = panel.querySelector('#vm-result');
  const form = panel.querySelector('#vm-form');
  const test = panel.querySelector('#vm-test');
  const errors = {
    admin_required: '需要管理员身份。', same_origin_required: '请从统一后台打开本页面后重试。',
    second_factor_required: '动态码或查看密钥不正确。', smtp_not_configured: '请先保存完整的发信配置。',
    smtp_credentials_incomplete: '请填入发信邮箱账号和专用密码。',
    test_recently_requested: '测试通知已请求，请稍后查看发送状态。',
    configuration_storage_unavailable: '暂时无法保存配置。', notification_worker_unavailable: '通知服务暂不可用。'
  };
  const element = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = String(text);
    return node;
  };
  const timestamp = value => {
    const number = Number(value);
    if (!Number.isFinite(number) || number <= 0) return '—';
    const date = new Date(number * 1000);
    if (!Number.isFinite(date.getTime())) return '—';
    return new Intl.DateTimeFormat('sv-SE', {timeZone: 'Asia/Singapore', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false}).format(date).replace(/-/g, '.');
  };
  const fresh = (value, now) => Number.isFinite(Number(value)) && Number(value) > 0 && now - Number(value) <= 15 && Number(value) <= now + 30;
  const asList = value => Array.isArray(value) ? value : [];
  function drawSources(data) {
    const container = panel.querySelector('#vm-sources');
    container.replaceChildren();
    const coverage = data.coverage || {}, groups = asList(coverage.sources), cursors = asList(data.sources), now = Date.now() / 1000;
    let total = 0, verified = 0;
    for (const group of groups) {
      const cursor = cursors.find(item => item.source_id === group.id);
      const policySources = asList(group.coverage && group.coverage.sources);
      const entries = policySources.length ? policySources : [{source_id: group.id}];
      for (const source of entries) {
        total++;
        const policy = source.policy || {}, problems = [], healthAt = Math.max(Number(source.last_seen) || 0, Number(source.policy_verified_at) || 0);
        if (group.error || (cursor && cursor.last_error) || source.last_error) problems.push('采集报错');
        if (!cursor || !fresh(cursor.last_polled_at, now)) problems.push('事件采集未及时更新');
        if (!fresh(healthAt, now)) problems.push('检测状态未及时更新');
        if (source.observable !== true || policy.observable !== true) problems.push('当前链路未确认可检测');
        if (!source.policy_verified_at || !asList(policy.confirmed_rules).length) problems.push('违规规则尚未核验');
        const ok = problems.length === 0;
        if (ok) verified++;
        const card = element('article', 'vm-source' + (ok ? '' : ' needs-attention'));
        card.dataset.source = String(group.id || '') + ':' + String(source.source_id || '');
        card.dataset.health = ok ? 'healthy' : 'attention';
        const head = element('div', 'vm-source-head');
        head.append(element('strong', '', source.source_id || group.id || '事件源'), element('span', 'vm-source-badge', ok ? '采集正常' : '需要关注'));
        card.append(head, element('p', 'vm-source-reason', ok ? '违规规则已核验，检测状态持续更新。' : Array.from(new Set(problems)).join(' · ')));
        card.append(element('p', 'muted', '采集更新 ' + timestamp(cursor && cursor.last_polled_at)), element('p', 'muted', '规则核验 ' + timestamp(source.policy_verified_at)));
        container.append(card);
      }
    }
    if (!total) container.append(element('p', 'vm-empty', '尚无已接入的检测来源；不会将缺少的采集视为正常。'));
    panel.querySelector('#vm-source-note').textContent = verified + ' / ' + total + ' 个检测来源正常';
    panel.querySelector('#vm-coverage').textContent = '仅对规则确认的违规事件发信；订阅请求次数和来源异常仍为风险提示。超过 15 秒未更新的来源会标记需要关注。首次启用从新事件开始，待发送通知会保留并重试。';
    return total === 0 || verified !== total;
  }
  const eventStates = {pending_config: '等待发信配置', queued: '等待发送', sending: '正在发送', retry: '等待重试', sent: '已发送'};
  function drawEvents(payload) {
    if (!payload || !Array.isArray(payload.events)) throw Error('events_schema_invalid');
    const rows = payload.events.slice(0, 100), body = panel.querySelector('#vm-events');
    body.replaceChildren();
    for (const event of rows) {
      const row = element('tr');
      row.dataset.eventState = event.eligible === 0 ? 'ignored' : event.state || 'unknown';
      const kind = event.kind === 'bt-block' ? 'BT 违规阻断' : event.kind === 'notification-test' ? '测试通知' : '其他事件';
      const status = event.eligible === 0 ? '仅记录，不通知' : eventStates[event.state] || '未进入通知队列';
      for (const [label, value] of [['事件时间', timestamp(event.ts)], ['用户', event.user || '—'], ['类型', kind], ['通知状态', status], ['已发送时间', timestamp(event.sent_at)]]) {
        const cell = element('td', '', value);
        cell.dataset.label = label;
        if (label === '通知状态') cell.className = 'vm-event-state';
        row.append(cell);
      }
      body.append(row);
    }
    if (!rows.length) {
      const row = element('tr'), cell = element('td', 'vm-empty', '尚无新的通知事件');
      cell.colSpan = 5;
      row.append(cell);
      body.append(row);
    }
    panel.querySelector('#vm-event-note').textContent = '最近 ' + rows.length + ' 条 · 新加坡时间';
  }
  async function getJson(path) {
    const response = await fetch('./api/violation-mail/' + path, {cache: 'no-store'});
    if (!response.ok) throw Error('notification_worker_unavailable');
    const data = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw Error('notification_response_invalid');
    return data;
  }
  let loading = false;
  async function load() {
    if (loading) return;
    loading = true;
    try {
      const [statusResult, eventsResult] = await Promise.allSettled([getJson('status'), getJson('events')]);
      if (statusResult.status === 'fulfilled') {
        const data = statusResult.value, needsAttention = drawSources(data);
        state.textContent = !data.configured ? '待配置发信邮箱' : data.state === 'degraded' || needsAttention ? '发信或采集需要关注' : '发信已配置';
        const q = data.counts || data.queue || {};
        counts.textContent = `待配置 ${q.pending_config || 0} · 等待 ${q.queued || 0} · 重试 ${q.retry || 0} · 已发送 ${q.sent || 0}`;
        test.disabled = !data.configured;
      } else {
        state.textContent = '通知服务暂不可用';
        test.disabled = true;
        panel.querySelector('#vm-source-note').textContent = '采集状态暂不可用，上次结果保留';
        for (const card of panel.querySelectorAll('.vm-source')) {
          card.dataset.health = 'attention';
          card.classList.add('needs-attention');
          card.querySelector('.vm-source-badge').textContent = '需要关注';
          card.querySelector('.vm-source-reason').textContent = '采集状态读取失败，上次结果不代表当前状态。';
        }
      }
      if (eventsResult.status === 'fulfilled') {
        try { drawEvents(eventsResult.value); }
        catch (_) { panel.querySelector('#vm-event-note').textContent = '通知记录暂不可用，上次记录保留'; }
      } else panel.querySelector('#vm-event-note').textContent = '通知记录暂不可用，上次记录保留';
    } finally { loading = false; }
  }
  async function protectedPost(path, payload) {
    const key = typeof askKey === 'function' ? askKey() : prompt('请输入现有的6位动态码或查看密钥');
    if (!key) return null;
    const mode = typeof sensitiveMode === 'string' ? sensitiveMode : 'totp';
    const headers = {'Content-Type': 'application/json'};
    headers[mode === 'totp' ? 'X-TOTP-Code' : 'X-View-Key'] = key;
    const response = await fetch('./api/violation-mail/' + path, {method: 'POST', headers, body: JSON.stringify(payload || {})});
    let data;
    try { data = await response.json(); }
    catch (_) { throw Error(response.status === 429 ? '操作较频繁，请稍后再试。' : '服务暂时无法响应，请稍后重试。'); }
    if (!response.ok) throw Error(response.status === 429 ? '操作较频繁，请稍后再试。' : errors[data.error] || '操作未完成，请检查配置与验证码。');
    return data;
  }
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = form.querySelector('button[type=submit]');
    submit.disabled = true;
    try {
      const data = Object.fromEntries(new FormData(form));
      data.port = Number(data.port);
      const saved = await protectedPost('config', data);
      if (saved) { form.elements.password.value = ''; result.textContent = '配置已保存，可发送测试通知验证投递。'; await load(); }
    } catch (error) { result.textContent = error.message; }
    finally { submit.disabled = false; }
  });
  test.addEventListener('click', async () => {
    test.disabled = true;
    try {
      const sent = await protectedPost('test');
      if (sent) { result.textContent = '测试通知已加入发送队列，邮件主题会明确标为“测试通知”。'; await load(); }
    } catch (error) { result.textContent = error.message; }
    finally { await load(); }
  });
  form.elements.username.addEventListener('change', () => {
    if (!form.elements.sender.value) form.elements.sender.value = form.elements.username.value;
  });
  load();
  setInterval(load, 10000);
})();

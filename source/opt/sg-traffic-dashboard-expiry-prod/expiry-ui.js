/* Staging-only overlay. Never alter the audited production page. */
(() => {
  if (typeof drawServers !== 'function') return;
  const original = drawServers;
  drawServers = function () {
    original();
    const whole = data && data.whole;
    if (!whole) return;
    if (data.expiry_stage_isolated) {
      document.getElementById('online').textContent = '未采集';
      document.getElementById('blocked').textContent = '未采集';
      let banner = document.getElementById('expiry-fixture-banner');
      if (!banner) {
        banner = node('div', 'panel', '');
        banner.id = 'expiry-fixture-banner';
        document.querySelector('main').prepend(banner);
      }
      banner.textContent = whole.expiry_preview_now ?
        '到期功能模拟预览 · 时间 ' + dateTime(whole.expiry_preview_now) +
        ' · 全部数据来自合成样例；非实时统计' :
        '隔离测试后台 · 仅使用独立流量数据库；实时连接与阻断统计未接入';
    }
    const cards = document.querySelectorAll('#servers > .server-card');
    for (const card of cards) {
      const title = card.querySelector('.server-title h3');
      const item = title && whole.servers && whole.servers[title.textContent];
      if (item && (title.textContent === 'BWH' || title.textContent === 'GoMami')) {
        const tags = (item.details && item.details.outbound_tags) || {};
        const missing = [];
        if (!Object.prototype.hasOwnProperty.call(tags, 'residential-out'))
          missing.push('kookey');
        if (!Object.prototype.hasOwnProperty.call(tags, 'residential-sg-trial'))
          missing.push('proxyhive.io');
        if (missing.length)
          card.append(node('div', 'muted',
            missing.join('、') + ' 独立应用标签：未采集；不能把缺失当作 0 B。'));
      }
      if (!item || !item.expired) continue;
      const badge = card.querySelector('.server-title span');
      if (badge) {
        badge.className = 'off';
        badge.textContent = item.snapshot_pending ? '到期 · 快照待核实' :
          '到期归档 · 截止 ' + dateTime(item.freeze_at);
      }
      const note = node('div', 'muted', item.snapshot_pending ?
        '未取得可核实的冻结快照，暂不展示到期后滚动数值。' :
        '真实最后测量：' + dateTime(item.last_measured_at) +
        '；截止时间并非伪造的实测时间。');
      card.append(note);
      const usage = item.historical_user_usage || [];
      if (usage.length) {
        const detail = node('details', '', '');
        detail.append(node('summary', '', '到期前可核实的近 30 天用户用量（留档）'));
        for (const row of usage) {
          detail.append(node('div', 'split-row', row.user + ' · ' + fmt(row.total)));
        }
        card.append(detail);
      }
    }
    let panel = document.getElementById('expiry-service-panel');
    if (!panel) {
      panel = node('section', 'panel', '');
      panel.id = 'expiry-service-panel';
      panel.append(node('h2', '', '已到期服务 · 历史快照'));
      const grid = node('div', 'server-grid', '');
      grid.id = 'expiry-service-grid';
      panel.append(grid);
      document.getElementById('servers').after(panel);
    }
    const grid = document.getElementById('expiry-service-grid');
    grid.textContent = '';
    const services = whole.retired_services || {};
    for (const name of ['proxyhive.io', 'kookey']) {
      const item = services[name];
      if (!item) continue;
      const card = node('section', 'server-card', '');
      card.append(node('h3', '', name + ' · 到期归档'));
      card.append(node('div', 'muted', '截止：' + dateTime(item.freeze_at) +
        '；真实最后测量：' + dateTime(item.last_measured_at)));
      card.append(node('div', 'muted', item.note || '没有可核实的服务级统计。'));
      for (const ingress of ['DMIT', 'BWH', 'GoMami']) {
        const source = (item.ingresses || {})[ingress] || {};
        card.append(node('div', 'split-row', ingress + ' · ' + fmt(source.bytes) +
          ' · 实测 ' + dateTime(source.measured_at)));
      }
      grid.append(card);
    }
    panel.hidden = !grid.children.length;
  };
  if (data) drawServers();
})();

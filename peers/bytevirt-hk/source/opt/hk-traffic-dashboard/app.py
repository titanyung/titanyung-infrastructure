#!/usr/bin/env python3
import collections
import html
import json
import os
import sqlite3
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("TRAFFIC_DB", "/var/lib/hk-traffic-dashboard/traffic.db")
PORT = int(os.environ.get("TRAFFIC_PORT", "8099"))
RETENTION_DAYS = 30
# ByteVirt ingress was restricted to NoSLA after the old direct service stopped.
CUTOVER_TS = 1790763303
hits = collections.defaultdict(collections.deque)
lock = threading.Lock()

PAGE = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HK ISP 流量中心</title>
<style>
:root{--bg:#07111f;--panel:#0d1a2d;--panel2:#12213a;--line:#223654;--text:#eef6ff;--muted:#8ea3bd;--teal:#20d7c5;--blue:#3d8bff;--pink:#ff5d92;--amber:#ffbf47}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#102947 0,transparent 32%),var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"PingFang SC",sans-serif}
.wrap{max-width:1440px;margin:auto;padding:28px}.head{display:flex;align-items:end;justify-content:space-between;gap:18px;margin-bottom:24px}.title{font-size:28px;font-weight:800;letter-spacing:.3px}.sub{color:var(--muted)}.badge{padding:7px 12px;border:1px solid #1d6c68;border-radius:999px;background:#0c2b31;color:var(--teal)}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.card,.panel{background:linear-gradient(145deg,rgba(18,33,58,.96),rgba(10,24,42,.96));border:1px solid var(--line);border-radius:18px;box-shadow:0 16px 38px rgba(0,0,0,.2)}.card{padding:20px}.label{color:var(--muted);font-size:13px}.num{font-size:27px;font-weight:800;margin-top:7px}.teal{color:var(--teal)}.blue{color:var(--blue)}.pink{color:var(--pink)}.amber{color:var(--amber)}
.grid{display:grid;grid-template-columns:1.05fr 1.95fr;gap:16px;margin-top:16px}.panel{padding:20px;overflow:hidden}.panel h2{font-size:17px;margin:0 0 16px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.toolbar select,.toolbar input{background:#09172a;border:1px solid var(--line);border-radius:10px;color:var(--text);padding:9px 11px}.tablebox{overflow-y:auto;overflow-x:hidden;max-height:520px}table{width:100%;max-width:100%;table-layout:auto;border-collapse:collapse}th,td{text-align:left;white-space:normal;overflow-wrap:anywhere;word-break:break-word;vertical-align:top;padding:11px 10px;border-bottom:1px solid rgba(34,54,84,.7)}th{position:sticky;top:0;background:#102039;color:var(--muted);font-size:12px}.user{font-weight:700}.pill{padding:3px 8px;border-radius:999px;background:#102e38;color:var(--teal);font-size:12px}.barrow{margin:12px 0}.barlabel{display:flex;justify-content:space-between;color:var(--muted);margin-bottom:6px}.bar{height:9px;border-radius:999px;background:#071526;overflow:hidden}.fill{height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--teal),var(--blue),var(--pink))}.empty{padding:30px;text-align:center;color:var(--muted)}
/* HK-ACCESS-TABLE-2026 */
.grid{grid-template-columns:minmax(270px,.72fr) minmax(0,2.28fr)}
.access-table{table-layout:fixed;min-width:820px}
.access-table th:nth-child(1){width:12%}.access-table th:nth-child(2){width:9%}.access-table th:nth-child(3){width:16%}.access-table th:nth-child(4){width:16%}.access-table th:nth-child(5){width:24%}.access-table th:nth-child(6){width:7%}.access-table th:nth-child(7){width:8%}.access-table th:nth-child(8){width:8%}
.access-table th{padding-top:10px;padding-bottom:10px;color:#79b2ff;font-weight:650;letter-spacing:.2px}
.access-table td,.access-table th{padding-left:6px;padding-right:6px}.access-table td{padding-top:9px;padding-bottom:9px;line-height:1.38;vertical-align:middle}
.access-table tbody tr{transition:background .18s ease,box-shadow .18s ease}
.access-table tbody tr:nth-child(even){background:rgba(9,23,42,.24)}
.access-table tbody tr:hover{background:rgba(61,139,255,.09);box-shadow:inset 3px 0 0 rgba(32,215,197,.72)}
.access-time-date,.access-time-clock{display:block;white-space:nowrap;overflow-wrap:normal;word-break:normal}.access-time-date{color:var(--text);font-weight:650}.access-time-clock{margin-top:2px;color:var(--muted);font-size:12px;font-variant-numeric:tabular-nums}
.access-user{color:#dce9fb;line-height:1.35}
.access-path{color:#73e6d8;font-weight:650;line-height:1.35}
.access-source{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;color:#bcd0e8;overflow-wrap:anywhere}
.access-source-ip,.access-source-port{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.access-source-port{color:#8ea3bd}
.access-destination{color:#e9f2ff;overflow-wrap:anywhere;word-break:normal}
.access-protocol,.access-traffic,.access-status{white-space:nowrap;overflow-wrap:normal;word-break:normal}
.protocol-chip,.status-chip{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;font-size:11px;line-height:1;padding:6px 8px;white-space:nowrap}
.protocol-chip{border:1px solid #284669;background:#0a1c33;color:#91bff4;font-weight:700;letter-spacing:.35px}
.status-chip{border:1px solid transparent;font-weight:700}.status-active{border-color:#176d66;background:#0b302f;color:#38e0cf}.status-closed{border-color:#294663;background:#10243a;color:#9eb2c9}
.access-traffic{font-variant-numeric:tabular-nums;color:#cfe0f5}
.route-cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px;margin-top:16px}.route-card{border:1px solid var(--line);border-radius:16px;padding:18px;background:linear-gradient(145deg,rgba(18,33,58,.96),rgba(10,24,42,.96))}.route-card h2{margin:0 0 8px;font-size:16px}.route-card .route-value{font-size:25px;font-weight:800}.route-card .route-sub{color:var(--muted);font-size:12px}.route-note{margin-top:10px;color:var(--muted);font-size:12px}.route-alert{color:var(--amber)}.access-path.route-relay{color:#79b2ff}.access-path.route-direct{color:var(--amber)}
@media(max-width:1180px){.grid{grid-template-columns:1fr}}
/* HK-SCROLLBAR-2026 */
html{scrollbar-color:#355372 #07111f;scrollbar-width:thin}
body{scrollbar-gutter:stable}html,body{max-width:100%;overflow-x:hidden}
*::-webkit-scrollbar{width:10px;height:10px}
*::-webkit-scrollbar-track{background:#07111f}
*::-webkit-scrollbar-thumb{min-height:44px;border:2px solid #07111f;border-radius:999px;background:linear-gradient(180deg,#355372,#223955)}
*::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,#20a999,#3d8bff)}
*::-webkit-scrollbar-corner{background:#07111f}
.tablebox{scrollbar-color:#3b6288 #0a1728;scrollbar-width:thin;scrollbar-gutter:stable}
.tablebox{overflow-x:auto}
.tablebox::-webkit-scrollbar{width:9px;height:9px}
.tablebox::-webkit-scrollbar-track{border-radius:999px;background:#0a1728}
.tablebox::-webkit-scrollbar-thumb{border:2px solid #0a1728;border-radius:999px;background:linear-gradient(90deg,#2a4665,#3d668c)}
.tablebox::-webkit-scrollbar-thumb:hover{background:linear-gradient(90deg,#20a999,#3d8bff)}
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.wrap{padding:18px}}@media(max-width:520px){.cards,.route-cards{grid-template-columns:1fr}.title{font-size:23px}}
</style></head><body><div class="wrap">
<div class="head"><div><div class="title">香港出口 · 流量与访问中心</div><div class="sub">DMIT 账号 · NoSLA 中转至 ByteVirt 香港 ISP · 明细保留 30 天</div></div><div class="badge" id="status">● 正在读取</div></div>
<div class="cards"><div class="card"><div class="label">今日总流量</div><div class="num teal" id="today">--</div></div><div class="card"><div class="label">30 天总流量</div><div class="num blue" id="month">--</div></div><div class="card"><div class="label">当前连接 / 用户</div><div class="num pink" id="online">--</div></div><div class="card"><div class="label">30 天自动阻断</div><div class="num amber" id="blocked">--</div></div></div>
<div class="route-cards"><div class="route-card"><h2>NoSLA 普通直出（历史，已停用）</h2><div class="route-value amber" id="route-nosla-today">--</div><div class="route-sub">历史今日 · 30 天 <span id="route-nosla-month">--</span>；不含 NAS 映射</div></div><div class="route-card"><h2>NoSLA → ByteVirt 香港 ISP</h2><div class="route-value blue" id="route-isp-today">--</div><div class="route-sub">今日 · 30 天 <span id="route-isp-month">--</span></div></div></div><div class="route-note" id="route-note">NAS 映射走独立 Rathole，不计入节点直出统计。</div>
<div class="grid"><div class="panel"><h2>用户用量（30 天）</h2><div id="bars"></div></div><div class="panel"><div class="toolbar"><h2 style="margin-right:auto">访问记录</h2><select id="user"><option value="">全部用户</option></select><select id="route"><option value="">全部路径</option><option value="nosla">NoSLA 普通直出（历史）</option><option value="bytevirt_hk_isp">NoSLA → ByteVirt 香港 ISP</option><option value="bytevirt_direct">ByteVirt 直连（历史 / 异常）</option></select><input id="q" placeholder="筛选目的地址"></div><div class="tablebox"><table class="access-table"><thead><tr><th>时间</th><th>用户</th><th>路径</th><th>来源</th><th>目的地址</th><th>协议</th><th>流量</th><th>状态</th></tr></thead><tbody id="records"></tbody></table></div></div></div>
<div class="panel" style="margin-top:16px"><h2>安全中心 · 最近阻断</h2><div class="tablebox"><table><thead><tr><th>时间</th><th>用户</th><th>来源</th><th>类型</th><th>详情</th></tr></thead><tbody id="events"></tbody></table></div></div>
</div><script>
const $=id=>document.getElementById(id), fmt=n=>{n=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(n<1000)return n.toFixed(n<10&&u!=='B'?2:1)+' '+u;n/=1000}return n.toFixed(2)+' PB'}, esc=s=>String(s??'');
async function load(){try{const u=$('user').value,q=$('q').value,route=$('route').value;const r=await fetch('/api/data?user='+encodeURIComponent(u)+'&q='+encodeURIComponent(q)+'&route='+encodeURIComponent(route));if(!r.ok)throw Error(r.status);const d=await r.json();$('today').textContent=fmt(d.summary.today);$('month').textContent=fmt(d.summary.month);$('online').textContent=d.summary.connections+' / '+d.summary.users;$('blocked').textContent=d.summary.blocked;$('status').textContent='● 在线 · '+new Date().toLocaleTimeString();
const paths=d.routes||{},nosla=paths.nosla||{},isp=paths.bytevirt_hk_isp||{},direct=paths.bytevirt_direct||{},after=d.post_cutover_direct||{};$('route-nosla-today').textContent=fmt(nosla.today);$('route-nosla-month').textContent=fmt(nosla.month);$('route-isp-today').textContent=fmt(isp.today);$('route-isp-month').textContent=fmt(isp.month);const bad=Number(after.nosla||0)+Number(after.bytevirt_direct||0);$('route-note').textContent='切换后普通直出记录 '+bad+' 条（NoSLA '+Number(after.nosla||0)+' / ByteVirt '+Number(after.bytevirt_direct||0)+'）；旧记录保留 30 天供审计。NAS 映射走独立 Rathole，不计入节点直出统计。'+(Number(direct.month)>0?' 历史 ByteVirt 直连 '+fmt(direct.month)+'。':'');$('route-note').classList.toggle('route-alert',bad>0);
const sel=$('user'),old=sel.value;sel.innerHTML='<option value="">全部用户</option>';d.users.forEach(x=>{const o=document.createElement('option');o.value=x.user;o.textContent=x.user;sel.appendChild(o)});sel.value=old;
const max=Math.max(1,...d.users.map(x=>x.total));$('bars').innerHTML=d.users.length?'': '<div class="empty">暂无用户流量</div>';d.users.forEach(x=>{const e=document.createElement('div');e.className='barrow';e.innerHTML='<div class="barlabel"><span class="user"></span><span></span></div><div class="bar"><div class="fill"></div></div>';e.querySelector('.user').textContent=x.user;e.querySelectorAll('span')[1].textContent=fmt(x.total);e.querySelector('.fill').style.width=Math.max(2,x.total/max*100)+'%';$('bars').appendChild(e)});
$('records').innerHTML='';d.records.forEach(x=>{
 const tr=document.createElement('tr');
 const dt=new Date(x.started*1000);
 const timeTd=document.createElement('td');timeTd.className='access-time';
 const dateSpan=document.createElement('span');dateSpan.className='access-time-date';dateSpan.textContent=dt.toLocaleDateString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit'});
 const clockSpan=document.createElement('span');clockSpan.className='access-time-clock';clockSpan.textContent=dt.toLocaleTimeString('zh-CN',{hour12:false});timeTd.append(dateSpan,clockSpan);tr.appendChild(timeTd);
 const addCell=(value,className)=>{const td=document.createElement('td');td.className=className;td.textContent=esc(value);tr.appendChild(td);return td};
 addCell(x.user,'user access-user');const old=x.started<d.cutover_ts;const path=x.route_class==='nosla'?'NoSLA 直出（'+(old?'历史':'异常')+'）':x.route_class==='bytevirt_direct'?'ByteVirt 直连（'+(old?'历史':'异常')+'）':x.path;addCell(path,'access-path '+(x.route_class==='bytevirt_hk_isp'?'route-relay':x.route_class==='nosla'||x.route_class==='bytevirt_direct'?'route-direct':''));
 const sourceTd=document.createElement('td');sourceTd.className='access-source';const source=String(x.source||'');const sourceParts=source.match(/^(.*):(\d+)$/);const sourceIp=document.createElement('span');sourceIp.className='access-source-ip';sourceIp.textContent=sourceParts?sourceParts[1]:source;sourceTd.appendChild(sourceIp);if(sourceParts){const sourcePort=document.createElement('span');sourcePort.className='access-source-port';sourcePort.textContent=':'+sourceParts[2];sourceTd.appendChild(sourcePort)}tr.appendChild(sourceTd);addCell(x.destination,'access-destination');
 const protocolTd=document.createElement('td');protocolTd.className='access-protocol';const protocol=document.createElement('span');protocol.className='protocol-chip';protocol.textContent=String(x.protocol||'-').toUpperCase();protocolTd.appendChild(protocol);tr.appendChild(protocolTd);
 addCell(fmt(x.upload+x.download),'access-traffic');
 const statusTd=document.createElement('td');statusTd.className='access-status';const status=document.createElement('span');const active=x.status==='active';status.className='status-chip '+(active?'status-active':'status-closed');status.textContent=active?'活跃':'已结束';statusTd.appendChild(status);tr.appendChild(statusTd);
 $('records').appendChild(tr)
});if(!d.records.length)$('records').innerHTML='<tr><td colspan="8" class="empty">暂无访问记录</td></tr>';
$('events').innerHTML='';d.events.forEach(x=>{const tr=document.createElement('tr');[new Date(x.ts*1000).toLocaleString(),x.user,x.source,x.kind,x.detail].forEach(v=>{const td=document.createElement('td');td.textContent=esc(v);tr.appendChild(td)});$('events').appendChild(tr)});if(!d.events.length)$('events').innerHTML='<tr><td colspan="5" class="empty">暂无阻断事件</td></tr>';
}catch(e){$('status').textContent='● 数据暂不可用'}}
$('user').onchange=load;$('route').onchange=load;$('q').oninput=()=>{clearTimeout(window.t);window.t=setTimeout(load,300)};load();setInterval(load,10000);
</script></body></html>'''


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def rate_limited(ip):
    now = time.time()
    with lock:
        q = hits[ip]
        while q and q[0] < now - 60:
            q.popleft()
        q.append(now)
        return len(q) > 120


class Handler(BaseHTTPRequestHandler):
    server_version = "HKTraffic/2"
    def log_message(self, fmt, *args):
        return
    def send_common(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
        if rate_limited(ip):
            return self.send_common(429, "text/plain; charset=utf-8", b"Too many requests")
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            return self.send_common(200, "text/html; charset=utf-8", PAGE.encode())
        if parsed.path == "/api/health":
            return self.send_common(200, "application/json", b'{"ok":true}')
        if parsed.path != "/api/data":
            return self.send_common(404, "text/plain; charset=utf-8", b"Not found")
        query = urllib.parse.parse_qs(parsed.query)
        user = query.get("user", [""])[0][:128]
        needle = query.get("q", [""])[0][:128]
        route = query.get("route", [""])[0]
        if route not in ("", "nosla", "bytevirt_hk_isp", "bytevirt_direct"):
            return self.send_common(400, "text/plain; charset=utf-8", b"Invalid route")
        now = int(time.time()); cutoff = now - RETENTION_DAYS * 86400; today = now - now % 86400
        try:
            conn = db()
            month = conn.execute("SELECT COALESCE(SUM(upload+download),0) n FROM traffic_hourly WHERE hour>=?", (cutoff,)).fetchone()["n"]
            day = conn.execute("SELECT COALESCE(SUM(upload+download),0) n FROM traffic_hourly WHERE hour>=?", (today,)).fetchone()["n"]
            routes = {name: {"today": 0, "month": 0} for name in
                      ("nosla", "bytevirt_hk_isp", "bytevirt_direct")}
            for row in conn.execute(
                "SELECT route_class, SUM(upload+download) month, "
                "SUM(CASE WHEN hour>=? THEN upload+download ELSE 0 END) today "
                "FROM traffic_hourly_route WHERE hour>=? GROUP BY route_class",
                (today, cutoff),
            ):
                if row["route_class"] in routes:
                    routes[row["route_class"]] = {"today": row["today"], "month": row["month"]}
            route_since = conn.execute(
                "SELECT MIN(hour) n FROM traffic_hourly_route"
            ).fetchone()["n"]
            post_cutover_direct = {"nosla": 0, "bytevirt_direct": 0}
            for row in conn.execute(
                "SELECT route_class, COUNT(*) n FROM access_records "
                "WHERE started>=? AND route_class IN ('nosla','bytevirt_direct') "
                "GROUP BY route_class", (CUTOVER_TS,),
            ):
                post_cutover_direct[row["route_class"]] = row["n"]
            users = [dict(r) for r in conn.execute("SELECT user,SUM(upload+download) total FROM traffic_hourly WHERE hour>=? GROUP BY user ORDER BY total DESC", (cutoff,))]
            active = conn.execute("SELECT COUNT(*) n,COUNT(DISTINCT user) u FROM access_records WHERE status='active' AND last_seen>=?", (now-15,)).fetchone()
            blocked = conn.execute("SELECT COUNT(*) n FROM security_events WHERE ts>=?", (cutoff,)).fetchone()["n"]
            where = ["started>=?"]; args = [cutoff]
            if user: where.append("user=?"); args.append(user)
            if needle: where.append("destination LIKE ?"); args.append("%"+needle+"%")
            if route: where.append("route_class=?"); args.append(route)
            columns = {r[1] for r in conn.execute("PRAGMA table_info(access_records)")}
            path_expr = "path" if "path" in columns else "'ByteVirt 香港 ISP' AS path"
            records = [dict(r) for r in conn.execute("SELECT user,source,destination,"+path_expr+",route_class,protocol,started,ended,upload,download,status FROM access_records WHERE "+" AND ".join(where)+" ORDER BY started DESC LIMIT 300", args)]
            events = [dict(r) for r in conn.execute("SELECT ts,user,source,kind,detail FROM security_events WHERE ts>=? ORDER BY ts DESC LIMIT 100", (cutoff,))]
            conn.close()
            payload = {"summary":{"today":day,"month":month,"connections":active["n"],"users":active["u"],"blocked":blocked},"routes":routes,"route_since":route_since,"post_cutover_direct":post_cutover_direct,"cutover_ts":CUTOVER_TS,"users":users,"records":records,"events":events,"retention_days":RETENTION_DAYS}
            return self.send_common(200, "application/json; charset=utf-8", json.dumps(payload,ensure_ascii=False).encode())
        except Exception as exc:
            body = json.dumps({"error":type(exc).__name__}).encode()
            return self.send_common(500, "application/json", body)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

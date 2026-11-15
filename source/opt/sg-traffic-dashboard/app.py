#!/usr/bin/env python3
import collections
import concurrent.futures
import html
import json
import os
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("TRAFFIC_DB", "/var/lib/sg-traffic-dashboard/traffic.db")
SUI_DB_PATH = os.environ.get("SUI_DB", "/usr/local/s-ui/db/s-ui.db")
WHOLE_DB_PATH = os.environ.get("WHOLE_TRAFFIC_DB", "/var/lib/sg-traffic-dashboard/whole.db")
PAGE_PATH = os.environ.get("TRAFFIC_PAGE_PATH", "/opt/sg-traffic-dashboard/traffic-page-v3.html")
PORT = int(os.environ.get("TRAFFIC_PORT", "8099"))
RETENTION_DAYS = 30
TRAFFIC_START_TS = int(os.environ.get("TRAFFIC_START_TS", "0"))
DMIT_LABEL = "DMIT-静态IP"
DMIT_CUTOVER_TS = 1790708224  # DMIT traffic services first started, 2026-09-30 02:57:04 CST.
HK_RELAY_CUTOVER_TS = 1790763303  # ByteVirt began allowing only NoSLA at the HK ingress.
AGGREGATE_TOKEN = os.environ.get("AGGREGATE_TOKEN", "")
REMOTE_SOURCES = (
    ("BWHLA", "https://node.titanyungty.top:31880/api/aggregate-source"),
    ("香港ISP", "https://hktraffic.titanyung.click/api/aggregate-source"),
)
hits = collections.defaultdict(collections.deque)
lock = threading.Lock()
api_cache = {}
base_cache = {}
api_cache_lock = threading.Lock()
api_build_lock = threading.Lock()
base_refresh_lock = threading.Lock()
base_refresh_state = {"attempted_at": 0.0}
API_CACHE_TTL = 20
FIRST_HOP_INGRESSES = ("DMIT", "BWH", "NoSLA", "GoMami", "Lazycat-SG")
EGRESS_ONLY_INGRESSES = ("进站待核实", "ByteVirt-HK ISP", "出站待核实")

PAGE = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>统一流量中心</title>
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
.access-route{display:block;margin-top:3px;color:#87a6c8;font-size:11.5px;font-weight:500;line-height:1.25}.access-route.route-relay{color:#79b2ff}.access-route.route-legacy{color:var(--amber)}
.access-source{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12.5px;color:#bcd0e8;overflow-wrap:anywhere}
.access-source-ip,.access-source-port{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.access-source-port{color:#8ea3bd}
.access-destination{color:#e9f2ff;overflow-wrap:anywhere;word-break:normal}
.access-protocol,.access-traffic,.access-status{white-space:nowrap;overflow-wrap:normal;word-break:normal}
.protocol-chip,.status-chip{display:inline-flex;align-items:center;justify-content:center;border-radius:999px;font-size:11px;line-height:1;padding:6px 8px;white-space:nowrap}
.protocol-chip{border:1px solid #284669;background:#0a1c33;color:#91bff4;font-weight:700;letter-spacing:.35px}
.status-chip{border:1px solid transparent;font-weight:700}.status-active{border-color:#176d66;background:#0b302f;color:#38e0cf}.status-closed{border-color:#294663;background:#10243a;color:#9eb2c9}
.access-traffic{font-variant-numeric:tabular-nums;color:#cfe0f5}
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
@media(max-width:900px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}.wrap{padding:18px}}@media(max-width:520px){.cards{grid-template-columns:1fr}.title{font-size:23px}}
</style></head><body><div class="wrap">
<div class="head"><div><div class="title">三服务器 · 统一流量与访问中心</div><div class="sub">DMIT-静态IP · BWHLA · 香港 ISP · 最近 30 天（含迁移前历史）</div></div><div class="badge" id="status">● 正在读取</div></div>
<div class="cards"><div class="card"><div class="label">今日总流量</div><div class="num teal" id="today">--</div></div><div class="card"><div class="label">30 天总流量</div><div class="num blue" id="month">--</div></div><div class="card"><div class="label">当前连接 / 用户</div><div class="num pink" id="online">--</div></div><div class="card"><div class="label">30 天自动阻断</div><div class="num amber" id="blocked">--</div></div></div>
<div class="grid"><div class="panel"><h2>各服务器用户用量（30 天）</h2><div id="bars"></div></div><div class="panel"><div class="toolbar"><h2 style="margin-right:auto">访问记录</h2><select id="server"><option value="">全部服务器</option><option value="DMIT-静态IP">DMIT-静态IP</option><option value="BWHLA">BWHLA</option><option value="香港ISP">香港ISP</option></select><select id="route"><option value="">全部路径</option><option value="relay">中转</option><option value="direct">直连</option><option value="legacy_direct">历史 / 异常直出</option></select><select id="user"><option value="">全部用户</option></select><input id="q" placeholder="筛选目的地址"></div><div class="tablebox"><table class="access-table"><thead><tr><th>时间</th><th>用户</th><th>服务器 / 路径</th><th>来源</th><th>目的地址</th><th>协议</th><th>流量</th><th>状态</th></tr></thead><tbody id="records"></tbody></table></div></div></div>
<div class="panel" style="margin-top:16px"><h2>安全中心 · 最近阻断</h2><div class="tablebox"><table><thead><tr><th>时间</th><th>用户</th><th>来源</th><th>类型</th><th>详情</th></tr></thead><tbody id="events"></tbody></table></div></div>
</div><script>
const $=id=>document.getElementById(id), fmt=n=>{n=Number(n||0);for(const u of ['B','KB','MB','GB','TB']){if(n<1000)return n.toFixed(n<10&&u!=='B'?2:1)+' '+u;n/=1000}return n.toFixed(2)+' PB'}, esc=s=>String(s??'');
async function load(){try{const u=$('user').value,q=$('q').value,s=$('server').value,route=$('route').value;const r=await fetch('/api/data?user='+encodeURIComponent(u)+'&q='+encodeURIComponent(q)+'&server='+encodeURIComponent(s)+'&route='+encodeURIComponent(route));if(!r.ok)throw Error(r.status);const d=await r.json();$('today').textContent=fmt(d.summary.today);$('month').textContent=fmt(d.summary.month);$('online').textContent=d.summary.connections+' / '+d.summary.users;$('blocked').textContent=d.summary.blocked;const online=Object.values(d.sources||{}).filter(x=>x==='online').length,total=Object.keys(d.sources||{}).length;$('status').textContent='● '+online+'/'+total+' 在线 · '+new Date().toLocaleTimeString();
const sel=$('user'),old=sel.value;sel.innerHTML='<option value="">全部用户</option>';[...new Set(d.users.map(x=>x.user))].forEach(name=>{const o=document.createElement('option');o.value=name;o.textContent=name;sel.appendChild(o)});sel.value=old;
const max=Math.max(1,...d.users.map(x=>x.total));$('bars').innerHTML=d.users.length?'': '<div class="empty">暂无用户流量</div>';d.users.forEach(x=>{const e=document.createElement('div');e.className='barrow';e.innerHTML='<div class="barlabel"><span class="user"></span><span></span></div><div class="bar"><div class="fill"></div></div>';e.querySelector('.user').textContent=x.server+' · '+x.user;e.querySelectorAll('span')[1].textContent=fmt(x.total);e.querySelector('.fill').style.width=Math.max(2,x.total/max*100)+'%';$('bars').appendChild(e)});
$('records').innerHTML='';d.records.forEach(x=>{
 const tr=document.createElement('tr');
 const dt=new Date(x.started*1000);
 const timeTd=document.createElement('td');timeTd.className='access-time';
 const dateSpan=document.createElement('span');dateSpan.className='access-time-date';dateSpan.textContent=dt.toLocaleDateString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit'});
 const clockSpan=document.createElement('span');clockSpan.className='access-time-clock';clockSpan.textContent=dt.toLocaleTimeString('zh-CN',{hour12:false});timeTd.append(dateSpan,clockSpan);tr.appendChild(timeTd);
 const addCell=(value,className)=>{const td=document.createElement('td');td.className=className;td.textContent=esc(value);tr.appendChild(td);return td};
 addCell(x.user,'user access-user');const serverTd=addCell(x.server,'access-path');const routeSpan=document.createElement('span');routeSpan.className='access-route '+(x.route_mode==='relay'?'route-relay':x.route_mode==='legacy_direct'||x.route_mode==='unexpected_direct'?'route-legacy':'');routeSpan.textContent=x.route_label||'路径待核实';serverTd.appendChild(routeSpan);
 const sourceTd=document.createElement('td');sourceTd.className='access-source';const source=String(x.source||'');const sourceParts=source.match(/^(.*):(\d+)$/);const sourceIp=document.createElement('span');sourceIp.className='access-source-ip';sourceIp.textContent=sourceParts?sourceParts[1]:source;sourceTd.appendChild(sourceIp);if(sourceParts){const sourcePort=document.createElement('span');sourcePort.className='access-source-port';sourcePort.textContent=':'+sourceParts[2];sourceTd.appendChild(sourcePort)}tr.appendChild(sourceTd);addCell(x.destination,'access-destination');
 const protocolTd=document.createElement('td');protocolTd.className='access-protocol';const protocol=document.createElement('span');protocol.className='protocol-chip';protocol.textContent=String(x.protocol||'-').toUpperCase();protocolTd.appendChild(protocol);tr.appendChild(protocolTd);
 addCell((x.upload+x.download)>0?fmt(x.upload+x.download):'—','access-traffic');
 const statusTd=document.createElement('td');statusTd.className='access-status';const status=document.createElement('span');const active=x.status==='active';status.className='status-chip '+(active?'status-active':'status-closed');status.textContent=active?'活跃':'已结束';statusTd.appendChild(status);tr.appendChild(statusTd);
 $('records').appendChild(tr)
});if(!d.records.length)$('records').innerHTML='<tr><td colspan="8" class="empty">暂无访问记录</td></tr>';
$('events').innerHTML='';d.events.forEach(x=>{const tr=document.createElement('tr');[new Date(x.ts*1000).toLocaleString(),x.user,x.source,x.kind,x.detail].forEach(v=>{const td=document.createElement('td');td.textContent=esc(v);tr.appendChild(td)});$('events').appendChild(tr)});if(!d.events.length)$('events').innerHTML='<tr><td colspan="5" class="empty">暂无阻断事件</td></tr>';
}catch(e){$('status').textContent='● 数据暂不可用'}}
$('server').onchange=load;$('route').onchange=load;$('user').onchange=load;$('q').oninput=()=>{clearTimeout(window.t);window.t=setTimeout(load,300)};load();setInterval(load,10000);
</script></body></html>'''
# The production expiry wrapper uses base.PAGE when the maintained HTML is
# missing. Never let that legacy embedded page reappear with obsolete ingress
# labels; keep a minimal safe fallback for the wrapper's script insertion.
PAGE = ('<!doctype html><html lang="zh-CN"><meta charset="utf-8">'
        '<title>统一流量中心暂不可用</title><body>'
        '<p>后台页面文件缺失；访问记录未被删除。请联系管理员修复。</p>'
        '</body></html>')


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def sui_db():
    conn = sqlite3.connect(
        "file:" + urllib.parse.quote(SUI_DB_PATH) + "?mode=ro",
        uri=True,
        timeout=10,
    )
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


def local_payload(user, needle):
    now = int(time.time())
    cutoff = max(now - RETENTION_DAYS * 86400, TRAFFIC_START_TS)
    today = max(now - now % 86400, TRAFFIC_START_TS)
    conn = db()
    sui = sui_db()
    try:
        # One grouped scan replaces three passes over the large S-UI stats table.
        buckets = sui.execute(
            "SELECT tag user,SUM(traffic) total,"
            "SUM(CASE WHEN date_time>=? THEN traffic ELSE 0 END) today "
            "FROM stats WHERE resource='user' AND date_time>=? "
            "GROUP BY tag ORDER BY total DESC", (today, cutoff)).fetchall()
        month = sum(int(row["total"] or 0) for row in buckets)
        day = sum(int(row["today"] or 0) for row in buckets)
        users = [{"user": row["user"], "total": row["total"]} for row in buckets]
        active = sui.execute("SELECT COUNT(*) n,COUNT(DISTINCT name) u FROM clients WHERE last_online>=?", (now-15,)).fetchone()
        blocked = conn.execute("SELECT COUNT(*) n FROM security_events WHERE ts>=?", (cutoff,)).fetchone()["n"]
        where = ["started>=?"]
        args = [cutoff]
        if user:
            where.append("user=?")
            args.append(user)
        if needle:
            where.append("destination LIKE ?")
            args.append("%"+needle+"%")
        columns = {r[1] for r in conn.execute("PRAGMA table_info(access_records)")}
        path_expr = "path" if "path" in columns else "'DMIT-静态IP' AS path"
        records = [dict(r) for r in conn.execute("SELECT user,source,destination,"+path_expr+",protocol,started,ended,upload,download,status FROM access_records WHERE "+" AND ".join(where)+" ORDER BY started DESC LIMIT 300", args)]
        events = [dict(r) for r in conn.execute("SELECT ts,user,source,kind,detail FROM security_events WHERE ts>=? ORDER BY ts DESC LIMIT 100", (cutoff,))]
        return {"summary":{"today":day,"month":month,"connections":active["n"],"users":active["u"],"blocked":blocked},"users":users,"records":records,"events":events}
    finally:
        sui.close()
        conn.close()


def remote_payload(url, user, needle):
    query = urllib.parse.urlencode({"user": user, "q": needle})
    request = urllib.request.Request(
        url + "?" + query,
        headers={"X-Traffic-Token": AGGREGATE_TOKEN, "User-Agent": "Titanyung-Traffic-Aggregator/1"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def classify_record(label, row):
    started = int(row.get("started", 0) or 0)
    if label == "香港ISP":
        source = str(row.get("source", ""))
        if source.startswith("45.78.70.23:") or row.get("route_class") == "bwh_bytevirt_hk_isp":
            return "BWH", "relay", "中转至：ByteVirt-HK ISP"
        route_class = row.get("route_class")
        if route_class == "bytevirt_hk_isp":
            return "NoSLA", "relay", "中转至：ByteVirt-HK ISP"
        if route_class in ("nosla", "bytevirt_direct"):
            exit_name = "NoSLA" if route_class == "nosla" else "ByteVirt"
            suffix = "历史" if started < HK_RELAY_CUTOVER_TS else "异常"
            mode = "legacy_direct" if started < HK_RELAY_CUTOVER_TS else "unexpected_direct"
            ingress = "NoSLA" if route_class == "nosla" else "ByteVirt-HK ISP"
            return ingress, mode, f"{exit_name} 直出（{suffix}）"
        return "ByteVirt-HK ISP", "unknown", "路径待核实"
    if label == DMIT_LABEL and started < DMIT_CUTOVER_TS:
        return "GoMami（历史）", "legacy_direct", "迁移前出站"
    if label == DMIT_LABEL:
        return "DMIT", "unknown", "单条连接缺少出站标记"
    if label == "BWHLA":
        return "BWH", "unknown", "单条连接缺少出站标记"
    return label, "unknown", "出站待核实"


def whole_payload():
    """Physical NIC totals since launch, plus separately identified app paths."""
    now = int(time.time())
    start = max(TRAFFIC_START_TS, now - RETENTION_DAYS * 86400)
    local = time.localtime(now)
    today = max(TRAFFIC_START_TS, int(time.mktime(
        (local.tm_year, local.tm_mon, local.tm_mday, 0, 0, 0, 0, 0, -1))))
    names = ("DMIT", "BWH", "NoSLA", "ByteVirt-HK ISP", "GoMami",
             "Lazycat-SG", "Lazycat-HKT")
    result = {name: {"in": None, "out": None, "today_in": None,
                     "today_out": None, "sampled_at": None, "proxy_app": None,
                     "proxy_wire": None, "mapping_wire": None,
                     "direct": None, "kookeey": None, "bytevirt": None,
                     "lazycat": None, "lazycat_hkt": None,
                     "static_outbound": {},
                     "static_wire": {}, "static_wire_sampled_at": None,
                     "static_wire_started_at": None,
                     "static_wire_discontinuities": None,
                     "details": {}} for name in names}
    if not os.path.isfile(WHOLE_DB_PATH):
        return {"started": TRAFFIC_START_TS, "servers": result,
                "summary": {"today_in": 0, "today_out": 0,
                            "month_in": 0, "month_out": 0}}
    conn = sqlite3.connect("file:" + urllib.parse.quote(WHOLE_DB_PATH) + "?mode=ro",
                           uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT server,SUM(delta_rx) rx,SUM(delta_tx) tx,"
            "SUM(CASE WHEN ts>=? THEN delta_rx ELSE 0 END) day_rx,"
            "SUM(CASE WHEN ts>=? THEN delta_tx ELSE 0 END) day_tx,MAX(ts) last_ts "
            "FROM samples WHERE ts>=? GROUP BY server", (today, today, start))
        for row in rows:
            if row["server"] not in result:
                continue
            item = result[row["server"]]
            item.update({"in": int(row["rx"] or 0), "out": int(row["tx"] or 0),
                         "today_in": int(row["day_rx"] or 0),
                         "today_out": int(row["day_tx"] or 0),
                         "sampled_at": int(row["last_ts"] or 0)})
            latest = conn.execute(
                "SELECT sui_json,hk_json FROM samples WHERE server=? ORDER BY ts DESC LIMIT 1",
                (row["server"],)).fetchone()
            if latest:
                sui = json.loads(latest["sui_json"])
                hk = json.loads(latest["hk_json"])
                if row["server"] == "GoMami":
                    # This host was added after the whole-host dashboard launch.
                    # Compare S-UI counters against its first NIC sample so the
                    # proxy and physical totals describe the same time window.
                    baseline_row = conn.execute(
                        "SELECT sui_json FROM samples WHERE server=? AND ts>=? "
                        "ORDER BY ts ASC LIMIT 1", (row["server"], start),
                    ).fetchone()
                    baseline = json.loads(baseline_row["sui_json"]) if baseline_row else {}
                    sui = {tag: max(0, int(total) - int(baseline.get(tag, 0)))
                           for tag, total in sui.items()}
                if row["server"] in ("DMIT", "BWH", "GoMami"):
                    item["direct"] = int(sui.get("direct", 0))
                    item["kookeey"] = int(sui.get("residential-out", 0))
                    for tag, provider in (("stage:nexip_sg", "NexIP SG"),
                                          ("stage:ip2up", "ip2up.com"),
                                          ("stage:proxyhive", "proxyhive.io")):
                        if tag in sui:
                            item["static_outbound"][provider] = int(sui[tag])
                    if row["server"] == "DMIT":
                        item["lazycat"] = int(sui.get("lazycat-sg-test", 0))
                        item["lazycat_hkt"] = int(sui.get("lazycat-hkt", 0))
                    item["proxy_app"] = sum(int(value) for value in sui.values())
                    item["details"] = {"outbound_tags": sui}
                elif row["server"] == "ByteVirt-HK ISP":
                    item["proxy_app"] = sum(int(value) for value in hk.values())
                    # This machine is the final HK egress, not a relay to itself.
                    item["direct"] = item["proxy_app"]
                    item["details"] = {"routes": hk}
        for row in conn.execute(
            "SELECT server,SUM(proxy_wire) proxy,SUM(mapping_wire) mapping "
            "FROM categories WHERE ts>=? GROUP BY server", (start,)):
            if row["server"] in result:
                item = result[row["server"]]
                if row["server"] == "NoSLA":
                    # NoSLA nft counters already cover both relay directions.
                    item["proxy_wire"] = int(row["proxy"] or 0)
                item["mapping_wire"] = int(row["mapping"] or 0)
        for server in ("DMIT", "BWH"):
            wire = conn.execute(
                "SELECT ts,totals_json,discontinuities,started_at "
                "FROM static_wire_samples "
                "WHERE server=? AND ts>=? ORDER BY ts DESC LIMIT 1",
                (server, start),
            ).fetchone()
            if wire:
                totals = json.loads(wire["totals_json"])
                item = result[server]
                item["static_wire_sampled_at"] = int(wire["ts"])
                item["static_wire_started_at"] = int(wire["started_at"])
                item["static_wire_discontinuities"] = int(wire["discontinuities"])
                item["static_wire"] = {
                    label: {"rx": int(totals[f"{key}-rx"]),
                            "tx": int(totals[f"{key}-tx"])}
                    for key, label in (("nexip", "NexIP SG"),
                                       ("ip2up", "ip2up.com"),
                                       ("proxyhive", "proxyhive.io"))
                }
        # Sum only measured sessions whose outbound was confirmed by the
        # collector at connection time.  A reused S-UI outbound tag can point
        # to different providers over its lifetime, so its cumulative stats
        # are unsuitable for historical per-provider attribution.
        for provider in ("NexIP SG", "ip2up.com", "proxyhive.io"):
            for ingress, total in conn.execute(
                "SELECT ingress,SUM(upload+download) FROM unified_records "
                "INDEXED BY idx_unified_dashboard_relay_started "
                "WHERE relay=? AND started>=? AND traffic_known=1 "
                "AND route_type IN ('直连','中转') AND route_type='中转' "
                "AND origin IN ('dmit','bwh') "
                "AND id>='sui:' AND id<'sui;' "
                "GROUP BY ingress", (provider, start)):
                if ingress in ("DMIT", "BWH"):
                    prior = result[ingress]["static_outbound"].get(provider, 0)
                    result[ingress]["static_outbound"][provider] = prior + int(total or 0)
        hk_routes = result["ByteVirt-HK ISP"]["details"].get("routes", {})
        if result["ByteVirt-HK ISP"]["sampled_at"]:
            bwh = result["BWH"]
            if bwh["sampled_at"]:
                bwh_to_hk = int(hk_routes.get("bwh_bytevirt_hk_isp", 0))
                bwh["bytevirt"] = bwh_to_hk
                bwh["proxy_app"] = int(bwh["proxy_app"] or 0) + bwh_to_hk
            nosla = result["NoSLA"]
            if nosla["sampled_at"]:
                nosla["bytevirt"] = int(hk_routes.get("bytevirt_hk_isp", 0))
        gomami = result["GoMami"]
        if gomami["sampled_at"]:
            first = conn.execute("SELECT MIN(ts) FROM samples WHERE server=? AND ts>=?",
                                 ("GoMami", start)).fetchone()[0]
            if first is not None:
                gomami["bytevirt"] = int(conn.execute(
                    "SELECT COALESCE(SUM(upload+download),0) FROM unified_records "
                    "INDEXED BY idx_unified_hk_gomami_src_ts "
                    "WHERE origin='hk' AND traffic_known=1 "
                    "AND source>='103.26.8.100:' AND source<'103.26.8.100;' "
                    "AND started>=? AND started<=?",
                    (max(start, int(first)), int(gomami["sampled_at"])),
                ).fetchone()[0])
        lazycat = result["Lazycat-SG"]
        if lazycat["sampled_at"] and result["DMIT"]["sampled_at"]:
            first = conn.execute("SELECT MIN(ts) FROM samples WHERE server=? AND ts>=?",
                                 ("Lazycat-SG", start)).fetchone()[0]
            before = conn.execute(
                "SELECT sui_json FROM samples WHERE server='DMIT' AND ts<? "
                "ORDER BY ts DESC LIMIT 1", (first,),
            ).fetchone() if first is not None else None
            latest = result["DMIT"]["details"].get("outbound_tags", {})
            if before is not None and "lazycat-sg-test" in latest:
                baseline = int(json.loads(before[0]).get("lazycat-sg-test", 0))
                lazycat["proxy_app"] = max(
                    0, int(latest["lazycat-sg-test"]) - baseline)
                lazycat["details"] = {"proxy_estimate_source": "DMIT outbound"}
        lazycat_hkt = result["Lazycat-HKT"]
        if lazycat_hkt["sampled_at"] and result["DMIT"]["sampled_at"]:
            first = conn.execute("SELECT MIN(ts) FROM samples WHERE server=? AND ts>=?",
                                 ("Lazycat-HKT", start)).fetchone()[0]
            before = conn.execute(
                "SELECT sui_json FROM samples WHERE server='DMIT' AND ts<? "
                "ORDER BY ts DESC LIMIT 1", (first,),
            ).fetchone() if first is not None else None
            latest = result["DMIT"]["details"].get("outbound_tags", {})
            if before is not None and "lazycat-hkt" in latest:
                baseline = int(json.loads(before[0]).get("lazycat-hkt", 0))
                lazycat_hkt["proxy_app"] = max(
                    0, int(latest["lazycat-hkt"]) - baseline)
                lazycat_hkt["details"] = {"proxy_estimate_source": "DMIT outbound"}
    finally:
        conn.close()
    summary = {"today_in": 0, "today_out": 0, "month_in": 0, "month_out": 0}
    for item in result.values():
        if item["sampled_at"]:
            summary["today_in"] += item["today_in"]
            summary["today_out"] += item["today_out"]
            summary["month_in"] += item["in"]
            summary["month_out"] += item["out"]
    return {"started": TRAFFIC_START_TS, "servers": result, "summary": summary}


def unified_records(query):
    """Separate confirmed first-hop sessions from egress-only observations."""
    now = int(time.time())
    cutoff = max(TRAFFIC_START_TS, now - RETENTION_DAYS * 86400)
    def field(name, maximum=128):
        return query.get(name, [""])[0][:maximum]
    def numeric(name, default, maximum):
        raw = field(name, 32)
        if not raw:
            return default
        value = int(raw)
        if value < 0 or value > maximum:
            raise ValueError("invalid " + name)
        return value
    start = max(cutoff, numeric("from_ts", cutoff, now + 86400))
    end = min(now + 86400, numeric("to_ts", now + 86400, now + 86400))
    page = numeric("page", 0, 100000)
    view = field("view", 32) or "first_hop"
    if view not in ("first_hop", "exit_observations"):
        raise ValueError("invalid record view")
    user, ingress, route_type = field("user"), field("server", 40), field("type", 16)
    relay, destination, status = field("relay", 40), field("q"), field("status", 16)
    min_bytes = numeric("min_bytes", 0, 10**15)
    min_seconds = numeric("min_seconds", 0, 10**9)
    if ingress and ingress not in FIRST_HOP_INGRESSES + ("进站待核实",):
        raise ValueError("invalid ingress")
    if route_type and route_type not in ("直连", "中转", "待核实"):
        raise ValueError("invalid route type")
    if relay and relay not in ("直连", "Kookeey", "ByteVirt-HK ISP", "DMIT",
                              "NoSLA", "出站待核实", "BWH", "GoMami",
                              "Lazycat-SG", "Lazycat-HKT", "NexIP SG",
                              "ip2up.com", "proxyhive.io"):
        raise ValueError("invalid relay")
    if status and status not in ("active", "closed"):
        raise ValueError("invalid status")
    if not os.path.isfile(WHOLE_DB_PATH):
        return [], 0, page, []
    where = ["started>=?", "started<=?", "traffic_known=1",
             "route_type IN ('直连','中转','待核实')"]
    args = [start, end]
    # The collector emits the labels in these two closed sets. The positive
    # predicates are indexable on the large production access-record table.
    # ByteVirt's obsolete stored ingress label belongs only in diagnostics.
    allowed_ingresses = (EGRESS_ONLY_INGRESSES if view == "exit_observations"
                         else FIRST_HOP_INGRESSES)
    where.append("ingress IN (" + ",".join("?" for _ in allowed_ingresses) + ")")
    args.extend(allowed_ingresses)
    for column, value in (("user", user), ("ingress", ingress),
                          ("route_type", route_type), ("relay", relay),
                          ("status", status)):
        if value:
            where.append(column + "=?")
            args.append(value)
    if destination:
        where.append("destination LIKE ?")
        args.append("%" + destination + "%")
    if min_bytes:
        where.append("traffic_known=1 AND upload+download>=?")
        args.append(min_bytes)
    if min_seconds:
        where.append("(CASE WHEN ended>started THEN ended-started "
                     "WHEN status='active' THEN ?-started ELSE NULL END)>=?")
        args.extend((now, min_seconds))
    conn = sqlite3.connect("file:" + urllib.parse.quote(WHOLE_DB_PATH) + "?mode=ro",
                           uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        clause = " AND ".join(where)
        # Keep the old verified count query/index choice for its 1M+ rows.
        # A separate small partial index counts uncertain rows. Mixing both
        # route classes in one WHERE defeats the existing partial index and
        # turns the default dashboard request into a full-table scan.
        route_predicate = "route_type IN ('直连','中转','待核实')"
        total = 0
        if route_type != "待核实":
            verified_clause = clause.replace(
                route_predicate, "route_type IN ('直连','中转')", 1)
            verified_table = "unified_records"
            if view == "exit_observations":
                verified_table += " INDEXED BY idx_unified_ingress"
            else:
                # SQLite otherwise prefers ingress lookup and performs over a
                # million table lookups for the default first-hop count.
                verified_table += " INDEXED BY idx_unified_dashboard_cover"
            total += conn.execute(
                "SELECT COUNT(*) n FROM " + verified_table +
                " WHERE " + verified_clause, args).fetchone()["n"]
        if route_type not in ("直连", "中转"):
            uncertain_clause = clause.replace(
                route_predicate, "route_type='待核实'", 1)
            total += conn.execute(
                "SELECT COUNT(*) n FROM unified_records "
                "INDEXED BY idx_unified_unverified_count WHERE " +
                uncertain_clause, args).fetchone()["n"]
        main_total = total
        # A static connection can start before the 30-day window and remain
        # active, or close inside it.  The primary key restricts this extra
        # query to the two static ingress hosts, leaving the large recent
        # records query and its covering indexes unchanged.
        long_where = list(where)
        long_where[0] = "started<?"
        long_where[1] = ("(CASE WHEN status='closed' THEN "
                         "COALESCE(ended,changed) ELSE changed END) BETWEEN ? AND ?")
        long_where.extend(("origin IN ('dmit','bwh')", "id>='static:'", "id<'static;'"))
        long_clause = " AND ".join(long_where)
        long_args = [start, start, end] + args[2:]
        long_total = conn.execute(
            "SELECT COUNT(*) n FROM unified_records WHERE " + long_clause,
            long_args).fetchone()["n"]
        total += long_total
        rows = []
        if page * 100 < total:
            # The first-hop IN filter otherwise makes SQLite scan and sort
            # roughly a million ingress-index rows for the first page. Read
            # recent rows in timestamp order, or use the user/ingress index
            # when narrowed to one account/host. Egress-only has a small
            # ingress slice and can use its ingress index directly.
            if view == "exit_observations":
                row_table = "unified_records INDEXED BY idx_unified_ingress"
            elif user:
                row_table = "unified_records INDEXED BY idx_unified_user"
            elif ingress:
                row_table = "unified_records INDEXED BY idx_unified_ingress"
            else:
                row_table = "unified_records INDEXED BY idx_unified_started"
            columns = ("origin,id,user,source,destination,ingress server,route_type,relay,"
                       "started,ended,upload,download,status,traffic_known")
            offset = page * 100
            if offset < main_total:
                rows = [dict(row) for row in conn.execute(
                    "SELECT " + columns + " FROM " + row_table + " WHERE " + clause +
                    " ORDER BY started DESC,origin,id LIMIT ? OFFSET ?",
                    args + [100, offset])]
            if len(rows) < 100 and long_total:
                long_offset = max(0, offset - main_total)
                rows.extend(dict(row) for row in conn.execute(
                    "SELECT " + columns + " FROM unified_records WHERE " + long_clause +
                    " ORDER BY started DESC,origin,id LIMIT ? OFFSET ?",
                    long_args + [100 - len(rows), long_offset]))
        if view == "exit_observations":
            for row in rows:
                # This is a new opt-in API view. Preserve the stored value in
                # a diagnostic field, but never expose it as a server name.
                row["stored_ingress"] = row["server"]
                row["server"] = None
                source = str(row.get("source") or "")
                peer = source.rsplit(":", 1)[0] if ":" in source else source
                if row["origin"] == "hk" and row["id"].startswith("hk:"):
                    row["observed_hop"] = {
                        "179.255.136.79": "DMIT", "45.78.70.23": "BWH",
                        "103.26.8.100": "GoMami",
                        "216.23.117.226": "NoSLA",
                    }.get(peer)
                    row["observed_exit"] = "ByteVirt-HK ISP"
                elif row["origin"] == "hk" and row["id"].startswith("nosla:"):
                    row["observed_hop"] = "NoSLA"
                    row["observed_exit"] = "NoSLA"
                else:
                    row["observed_hop"] = None
                    row["observed_exit"] = (
                        row["relay"] if row["relay"] in
                        ("DMIT", "BWH", "GoMami", "NoSLA", "ByteVirt-HK ISP",
                         "Lazycat-SG", "Lazycat-HKT", "Kookeey", "NexIP SG",
                         "ip2up.com", "proxyhive.io") else None)
                row["first_hop_confirmed"] = False
        users = [row[0] for row in conn.execute(
            "SELECT DISTINCT user FROM unified_records WHERE started>=? "
            "AND traffic_known=1 AND route_type IN ('直连','中转','待核实') ORDER BY user",
            (cutoff,))]
        return rows, total, page, users
    finally:
        conn.close()


def server_user_usage():
    """Count each observed host once, not every HK row as a client ingress."""
    if not os.path.isfile(WHOLE_DB_PATH):
        return []
    cutoff = max(TRAFFIC_START_TS, int(time.time()) - RETENTION_DAYS * 86400)
    conn = sqlite3.connect("file:" + urllib.parse.quote(WHOLE_DB_PATH) + "?mode=ro",
                           uri=True, timeout=5)
    try:
        # The production covering index does not contain origin. Keep the fast
        # all-ingress scan, then cancel HK-origin rows exactly once before
        # crediting their observed NoSLA/ByteVirt host. This avoids counting
        # terminal egress as first-hop usage or doing 1M+ origin table lookups.
        rows = conn.execute(
            "SELECT server,user,SUM(bytes) total FROM ("
            "SELECT ingress server,user,upload+download bytes "
            "FROM unified_records INDEXED BY idx_unified_dashboard_cover "
            "WHERE started>=? AND traffic_known=1 AND route_type IN ('直连','中转') "
            "UNION ALL "
            "SELECT ingress server,user,-(upload+download) bytes "
            "FROM unified_records INDEXED BY idx_unified_hk_firsthop_cover "
            "WHERE started>=? AND origin='hk' "
            "AND traffic_known=1 AND route_type IN ('直连','中转') UNION ALL "
            "SELECT relay server,user,upload+download bytes "
            "FROM unified_records INDEXED BY idx_unified_hk_usage "
            "WHERE started>=? AND origin='hk' AND traffic_known=1 "
            "AND route_type='中转' "
            "AND relay IN ('NoSLA','ByteVirt-HK ISP') UNION ALL "
            "SELECT relay server,user,upload+download bytes "
            "FROM unified_records INDEXED BY idx_unified_ingress "
            "WHERE started>=? AND origin='hk' AND ingress='进站待核实' "
            "AND traffic_known=1 AND route_type='待核实' "
            "AND relay IN ('NoSLA','ByteVirt-HK ISP') UNION ALL "
            # A measured, first-hop-known legacy session remains host usage
            # even when its outbound class was not captured. Exclude HK
            # egress rows, which would double-count a host upstream.
            "SELECT ingress server,user,upload+download bytes "
            "FROM unified_records INDEXED BY idx_unified_unverified_count "
            "WHERE started>=? AND origin!='hk' AND traffic_known=1 "
            "AND route_type='待核实' AND ingress IN "
            "('DMIT','BWH','NoSLA','GoMami','Lazycat-SG') UNION ALL "
            "SELECT 'Lazycat-HKT' server,user,upload+download bytes "
            "FROM unified_records WHERE started>=? AND origin='dmit' "
            "AND relay='Lazycat-HKT' AND traffic_known=1 "
            "AND route_type='中转') "
            "GROUP BY server,user HAVING SUM(bytes)>0 ORDER BY server,total DESC",
            (cutoff, cutoff, cutoff, cutoff, cutoff, cutoff))
        return [{"server": server, "user": user, "total": int(total)}
                for server, user, total in rows]
    finally:
        conn.close()


def aggregate_payload(user, needle, server_filter, route_filter=""):
    payloads = []
    sources = {}
    # Start independent network and NIC reads before the S-UI database scan.
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        whole_future = executor.submit(whole_payload)
        remote_futures = {
            label: executor.submit(remote_payload, url, user, needle)
            for label, url in REMOTE_SOURCES
            if AGGREGATE_TOKEN and (not server_filter or server_filter == label)
        }
        if not server_filter or server_filter in (DMIT_LABEL, "gomamiSG"):
            try:
                payloads.append((DMIT_LABEL, local_payload(user, needle)))
                sources[DMIT_LABEL] = "online"
            except Exception:
                sources[DMIT_LABEL] = "offline"
        for label, url in REMOTE_SOURCES:
            if server_filter and server_filter != label:
                continue
            try:
                payloads.append((label, remote_futures[label].result()))
                sources[label] = "online"
            except Exception:
                sources[label] = "offline"
        whole = whole_future.result()

    summary = {"today":0,"month":0,"connections":0,"users":0,"blocked":0}
    users = []
    records = []
    events = []
    for label, data in payloads:
        for key in summary:
            summary[key] += int(data.get("summary", {}).get(key, 0) or 0)
        for item in data.get("users", []):
            row = dict(item)
            row["server"] = label
            users.append(row)
        for item in data.get("records", []):
            row = dict(item)
            row["server"], row["route_mode"], row["route_label"] = classify_record(label, row)
            if route_filter and row["route_mode"] != route_filter:
                if not (route_filter == "legacy_direct" and row["route_mode"] == "unexpected_direct"):
                    continue
            records.append(row)
        for item in data.get("events", []):
            row = dict(item)
            row["detail"] = "[" + label + "] " + str(row.get("detail", ""))
            events.append(row)
    users.sort(key=lambda row: int(row.get("total", 0) or 0), reverse=True)
    records.sort(key=lambda row: int(row.get("started", 0) or 0), reverse=True)
    events.sort(key=lambda row: int(row.get("ts", 0) or 0), reverse=True)
    return {"summary":summary,"users":users,"records":records[:900],"events":events[:300],"sources":sources,"retention_days":RETENTION_DAYS,"whole":whole}


def refresh_base_payload():
    """Refresh the costly aggregate without delaying an existing page view."""
    try:
        payload = aggregate_payload("", "", "", "")
        payload["server_user_usage"] = server_user_usage()
        base_cache["data"] = (time.monotonic(), payload)
    except Exception as exc:
        print("background dashboard refresh failed: " + type(exc).__name__, flush=True)
    finally:
        base_refresh_lock.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "DMITTraffic/2"
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
            if os.path.isfile(PAGE_PATH):
                with open(PAGE_PATH, "rb") as stream:
                    return self.send_common(200, "text/html; charset=utf-8", stream.read())
            # The embedded legacy page predates first-hop attribution. If the
            # maintained page is missing, fail closed instead of showing an
            # old interface that can mislabel ByteVirt as an entry server.
            return self.send_common(503, "text/plain; charset=utf-8",
                                    b"Dashboard page unavailable")
        if parsed.path == "/api/health":
            return self.send_common(200, "application/json", b'{"ok":true}')
        if parsed.path != "/api/data":
            return self.send_common(404, "text/plain; charset=utf-8", b"Not found")
        query = urllib.parse.parse_qs(parsed.query)
        user = query.get("user", [""])[0][:128]
        needle = query.get("q", [""])[0][:128]
        server_filter = query.get("server", [""])[0][:32]
        route_filter = query.get("route", [""])[0][:32]
        if route_filter not in ("", "relay", "direct", "legacy_direct"):
            return self.send_common(400, "text/plain; charset=utf-8", b"Invalid route")
        try:
            cache_key = parsed.query
            with api_cache_lock:
                cached = api_cache.get(cache_key)
            if cached and time.monotonic() - cached[0] < API_CACHE_TTL:
                return self.send_common(200, "application/json; charset=utf-8", cached[1])
            # Browser polling can overlap a slow database read. Build one
            # response at a time instead of launching identical full scans.
            with api_build_lock:
                with api_cache_lock:
                    cached = api_cache.get(cache_key)
                if cached and time.monotonic() - cached[0] < API_CACHE_TTL:
                    body = cached[1]
                else:
                    base = base_cache.get("data")
                    if not base:
                        base_payload = aggregate_payload("", "", "", "")
                        base_payload["server_user_usage"] = server_user_usage()
                        base_cache["data"] = (time.monotonic(), base_payload)
                    else:
                        base_payload = base[1]
                        now = time.monotonic()
                        if (now - base[0] >= 60 and
                                now - base_refresh_state["attempted_at"] >= 30 and
                                base_refresh_lock.acquire(blocking=False)):
                            base_refresh_state["attempted_at"] = now
                            threading.Thread(target=refresh_base_payload,
                                             daemon=True).start()
                    payload = dict(base_payload)
                    records, total, page, all_users = unified_records(query)
                    payload["records"] = records
                    payload["records_total"] = total
                    payload["records_page"] = page
                    payload["records_page_size"] = 100
                    payload["record_users"] = all_users
                    body = json.dumps(payload, ensure_ascii=False).encode()
                    with api_cache_lock:
                        if len(api_cache) >= 64:
                            api_cache.clear()
                        api_cache[cache_key] = (time.monotonic(), body)
            return self.send_common(200, "application/json; charset=utf-8", body)
        except (BrokenPipeError, ConnectionResetError):
            # Nginx or a browser may disconnect while an old request finishes.
            return
        except ValueError:
            return self.send_common(400, "application/json", b'{"error":"invalid filter"}')
        except Exception as exc:
            body = json.dumps({"error":type(exc).__name__}).encode()
            return self.send_common(500, "application/json", body)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

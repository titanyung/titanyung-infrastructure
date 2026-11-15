#!/usr/bin/env python3

import json
import os
import copy
from pathlib import Path
import uuid
import sys
# The main policy release owns these versioned readers. This script lives
# beside historical modules in /opt/submerge; prefer the actually published
# topology readers before any dependent import can cache an older revision.
if not sys.path or sys.path[0] != '/opt/submerge-topology':
    sys.path.insert(0, '/opt/submerge-topology')
from flask import Flask, request, jsonify, Response
from five_group_stage import ALL, GOOGLE, HK, STREAMING, VPS, OTHER, LEGACY_RULE_TARGETS


APP = Flask(__name__)

RULE_FILE = "/var/lib/submerge/route_rules.json"
NETWORK_PLAN_PATH = Path('/etc/submerge-topology/network-plan.json')
RULE_UI_VERSION = '20261109-server-routing-1'
RETIRED_TARGET_LABEL = '目标已停用'


# ============================================================
# 支持的匹配类型
# ============================================================

MATCH_TYPES = {
    "DOMAIN": "完整域名",
    "DOMAIN-SUFFIX": "域名后缀",
    "DOMAIN-KEYWORD": "域名关键词",

    "IP-CIDR": "IPv4 / CIDR",

    "PROCESS-NAME": "应用进程名",
    "PROCESS-PATH": "应用路径",

    "GEOIP": "国家 / 地区 IP",
    "GEOSITE": "GeoSite",

    "MATCH": "最终兜底",
}


# ============================================================
# 后台显示名 → Clash策略名
# ============================================================

GROUP_TARGETS = (ALL, GOOGLE, HK, STREAMING, VPS, OTHER)

# These are the same names emitted by the public subscription builder.  The
# hidden "自动" helper is not a destination for administrator rules.
TARGETS = {
    "DIRECT": "🟢 直连",
    **{name: name for name in GROUP_TARGETS},
}

# Existing rules must remain visible and editable without silently changing
# their meaning.  They are not offered when creating a new rule.
LEGACY_TARGET_LABELS = {
    "AI工具": "AI工具",
    "DMIT→kookey（2027-01-15 01:42到期）": "🟦 DMIT→kookey（2027-01-15 01:42到期）",
    "DMIT-静态IP": "🟦 DMIT→kookey（旧规则名兼容）",
    "BWH": "🟪 BWH",
    "gomamiSG": "🟦 DMIT→kookey（旧规则名兼容）",
    "大陆-TVB": "🇭🇰 NoSLA → ByteVirt（兼容名）",
    "大陆-TVB→解锁TVB": "🇭🇰 DMIT → ByteVirt 香港 ISP",
    "奶昔": "🥤 奶昔",
    "paoluz": "🦊 paoluz",
}


def target_contract():
    """Return the active subscription groups without rewriting stored rules.

    The durable root-only marker is authoritative. A malformed marker raises
    rather than reverting to legacy destinations or allowing obsolete targets.
    """
    if not os.path.lexists(str(NETWORK_PLAN_PATH)):
        return {'targets': dict(TARGETS), 'legacy_labels': dict(LEGACY_TARGET_LABELS),
                'legacy_group_targets': dict(LEGACY_RULE_TARGETS),
                'summary_targets': {'hk': HK, 'all': ALL}, 'plan': 'legacy'}
    from network_runtime import load_network_plan, PLAN_ID
    from new_topology import (PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER, PLAN_STREAMING,
                              PLAN_PAOLUZ)
    plan = load_network_plan(NETWORK_PLAN_PATH)
    if plan is None:
        raise ValueError('network_plan_intent_missing')
    if plan.get('plan') == 'network-plan-20261109':
        from routing_rule_catalog import contract
        return contract(plan, LEGACY_RULE_TARGETS)
    groups = (ALL, PLAN_GOOGLE, PLAN_TVB, PLAN_HK_OTHER,
              VPS, OTHER, PLAN_PAOLUZ)
    targets = {'DIRECT': TARGETS['DIRECT'], **{name: name for name in groups}}
    aliases = dict(LEGACY_RULE_TARGETS)
    aliases.update({GOOGLE: PLAN_GOOGLE, HK: PLAN_HK_OTHER, STREAMING: OTHER,
        '✈️ 机场paoluz': PLAN_PAOLUZ, 'paoluz': PLAN_PAOLUZ, 'Paoluz': PLAN_PAOLUZ,
        'Paoluz-All': PLAN_PAOLUZ, '🦊 PAOLUZ': PLAN_PAOLUZ, '🦊 机场paoluz': PLAN_PAOLUZ,
        '机场paoluz': PLAN_PAOLUZ, '断线备用': PLAN_PAOLUZ,
        '币安': OTHER, '🪙 币安': OTHER,
        '谷歌全系（不含流媒体）与AI': PLAN_GOOGLE,
        '🤖 谷歌全系（不含流媒体）与AI': PLAN_GOOGLE,
        'google（不含youtube）、chatgpt': PLAN_GOOGLE,
        '🤖 google（不含youtube）、chatgpt': PLAN_GOOGLE,
        'google（不含youtube）、chatgpt、claude': PLAN_GOOGLE,
        '🤖 google（不含youtube）、chatgpt、claude': PLAN_GOOGLE,
        'chatgpt、claude、google（不含youtube）': PLAN_GOOGLE,
        'TVB&viu tv': PLAN_TVB, '🇭🇰 TVB&viu tv': PLAN_TVB,
        'TVB、viu tv': PLAN_TVB, '✈️ paoluz': PLAN_PAOLUZ,
        'HK其他': PLAN_HK_OTHER, '非CN&HK流媒体的流媒体': OTHER,
        PLAN_STREAMING: OTHER})
    # Resolve historical raw aliases through their old emoji labels exactly as
    # the subscription renderer does. TVB aliases are the explicit exception.
    aliases = {key: aliases.get(value, value) for key, value in aliases.items()}
    aliases.update({'大陆-TVB': PLAN_TVB, '大陆-TVB→解锁TVB': PLAN_TVB})
    labels = dict(LEGACY_TARGET_LABELS)
    labels.update({key: targets[value] for key, value in aliases.items() if value in targets})
    return {'targets': targets, 'legacy_labels': labels, 'legacy_group_targets': aliases,
            'summary_targets': {'hk': PLAN_HK_OTHER, 'tvb': PLAN_TVB, 'all': ALL}, 'plan': PLAN_ID}


def canonical_target(value, contract):
    """Resolve display meaning without exposing or editing retired names."""
    if not isinstance(value, str):
        return None
    seen = set()
    while value in contract['legacy_group_targets'] and value not in seen:
        seen.add(value)
        replacement = contract['legacy_group_targets'][value]
        if replacement == value:
            break
        value = replacement
    return value if value in contract['targets'] else None


def display_data(data, contract):
    """Project current names at the API boundary; stored/audit data stays raw."""
    output = copy.deepcopy(data)
    for rule in output.get('rules', []):
        if not isinstance(rule, dict):
            continue
        target = canonical_target(rule.get('target'), contract)
        rule['target'] = target or ''
        rule['target_label'] = contract['targets'].get(target, RETIRED_TARGET_LABEL)
        rule['target_status'] = 'active' if target else 'retired'
    output['target_catalog_version'] = RULE_UI_VERSION
    return output


@APP.after_request
def prevent_stale_rule_ui(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Submerge-Rules-UI-Version'] = RULE_UI_VERSION
    return response


def load_data():
    if not os.path.exists(RULE_FILE):
        return {"rules": []}

    try:
        with open(RULE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return {"rules": []}

        if not isinstance(data.get("rules"), list):
            data["rules"] = []

        return data

    except Exception:
        return {"rules": []}


def save_data(data):
    temp = RULE_FILE + ".tmp"

    with open(temp, "w", encoding="utf-8") as f:
        json.dump(
            data,
            f,
            ensure_ascii=False,
            indent=2,
        )

    os.replace(temp, RULE_FILE)

    os.chmod(
        RULE_FILE,
        0o600,
    )


# ============================================================
# HTML
# ============================================================

HTML = r'''
<!doctype html>
<html lang="zh-CN">
<head>

<meta charset="utf-8">

<meta name="viewport"
      content="width=device-width,initial-scale=1">

<title>分流规则管理</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: #0f1115;
  color: #e8e8ea;
  font-family:
    Inter,
    "PingFang SC",
    "Microsoft YaHei",
    sans-serif;
}

.container {
  max-width: 1500px;
  margin: auto;
  padding: 28px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.title {
  font-size: 26px;
  font-weight: 700;
}

.subtitle {
  margin-top: 7px;
  color: #9297a3;
  font-size: 14px;
}

.actions {
  display: flex;
  gap: 10px;
}

button {
  border: 0;
  border-radius: 10px;
  padding: 10px 15px;
  cursor: pointer;
  font-size: 14px;
}

.primary {
  background: #7167f9;
  color: white;
}

.secondary {
  background: #242832;
  color: #ddd;
}

.danger {
  background: #3b1d24;
  color: #ff8d99;
}

.stats {
  display: grid;
  grid-template-columns:
    repeat(4,minmax(0,1fr));
  gap: 12px;
  margin-bottom: 22px;
}

.stat {
  background: #181b21;
  border: 1px solid #292d36;
  border-radius: 14px;
  padding: 16px;
}

.stat-label {
  color: #8e94a0;
  font-size: 13px;
}

.stat-value {
  margin-top: 7px;
  font-size: 25px;
  font-weight: 700;
}

.toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}

input,
select {
  background: #181b21;
  color: #eee;
  border: 1px solid #30343e;
  border-radius: 9px;
  min-height: 42px;
  padding: 0 12px;
  font-size: 14px;
}

.search {
  flex: 1;
  min-width: 220px;
}

.panel {
  border: 1px solid #292d36;
  background: #15181e;
  border-radius: 15px;
  overflow: hidden;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  text-align: left;
  padding: 13px 14px;
  font-size: 12px;
  color: #9096a2;
  background: #1b1e25;
}

td {
  border-top: 1px solid #292d36;
  padding: 13px 14px;
  vertical-align: middle;
}

.value {
  font-family: ui-monospace, monospace;
}

.tag {
  display: inline-flex;
  padding: 6px 9px;
  border-radius: 8px;
  background: #252933;
  font-size: 13px;
}

.target-DIRECT {
  color: #55d98b;
}

.target-Paoluz-HK {
  color: #ffb14c;
}

.target-Proxy {
  color: #75a7ff;
}

.row-actions {
  display: flex;
  gap: 6px;
}

.empty {
  padding: 50px;
  text-align: center;
  color: #777d89;
}

.modal-bg {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.65);
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal {
  width: min(560px,100%);
  background: #191c22;
  border: 1px solid #30343e;
  border-radius: 16px;
  padding: 22px;
}

.form-row {
  margin-bottom: 16px;
}

.form-row label {
  display: block;
  color: #9da2ad;
  margin-bottom: 7px;
  font-size: 13px;
}

.form-row input,
.form-row select {
  width: 100%;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 20px;
}

.switch {
  width: 46px;
  height: 25px;
  accent-color: #7167f9;
}

@media(max-width:800px) {

  .stats {
    grid-template-columns:
      repeat(2,minmax(0,1fr));
  }

  .panel {
    overflow-x: auto;
  }

  table {
    min-width: 900px;
  }

  .container {
    padding: 16px;
  }
}

</style>

</head>

<body>

<div class="container">

  <div class="header">

    <div>

      <div class="title">
        🛰️ 分流规则管理
      </div>

      <div class="subtitle" id="subtitle">
        分流出口与订阅分组同步
      </div>

    </div>

    <div class="actions">

      <button
        class="secondary"
        onclick="exportRules()">
        导出
      </button>

      <button
        class="primary"
        onclick="openAdd()">
        ＋ 新增规则
      </button>

    </div>

  </div>


  <div class="stats" id="stats">

    <div class="stat">
      <div class="stat-label">
        全部规则
      </div>
      <div class="stat-value" id="total">
        0
      </div>
    </div>

    <div class="stat">
      <div class="stat-label">
        DIRECT
      </div>
      <div class="stat-value" id="direct">
        0
      </div>
    </div>

  </div>


  <div class="toolbar">

    <input
      id="search"
      class="search"
      placeholder="搜索域名、IP、备注..."
      oninput="render()">

    <select
      id="targetFilter"
      onchange="render()">
    </select>

  </div>


  <div class="panel">

    <table>

      <thead>
        <tr>
          <th>启用</th>
          <th>优先级</th>
          <th>匹配方式</th>
          <th>域名 / IP</th>
          <th>出口</th>
          <th>备注</th>
          <th>操作</th>
        </tr>
      </thead>

      <tbody id="rows">
      </tbody>

    </table>

    <div
      id="empty"
      class="empty"
      style="display:none">
      暂无规则
    </div>

  </div>

</div>


<div
  id="modalBg"
  class="modal-bg">

  <form
    class="modal"
    onsubmit="saveRule(event)">

    <h2 id="modalTitle">
      新增规则
    </h2>

    <input
      id="ruleId"
      type="hidden">


    <div class="form-row">

      <label>
        匹配方式
      </label>

      <select id="matchType">

        <option value="DOMAIN">
          完整域名
        </option>

        <option value="DOMAIN-SUFFIX">
          域名后缀
        </option>

        <option value="DOMAIN-KEYWORD">
          域名关键词
        </option>

        <option value="IP-CIDR">
          IP / CIDR
        </option>

        <option value="PROCESS-NAME">
          应用进程名
        </option>

        <option value="PROCESS-PATH">
          应用路径
        </option>

        <option value="GEOIP">
          国家 / 地区 IP
        </option>

        <option value="GEOSITE">
          GeoSite
        </option>

        <option value="MATCH">
          最终兜底
        </option>

      </select>

    </div>


    <div class="form-row">

      <label>
        域名 / IP
      </label>

      <input
        id="ruleValue"
        required
        placeholder="例如 example.com 或 1.2.3.0/24">

    </div>


    <div class="form-row">

      <label>
        出口
      </label>

      <select id="target"></select>

    </div>


    <div class="form-row">

      <label>
        优先级（数字越小越优先）
      </label>

      <input
        id="priority"
        type="number"
        value="100"
        min="1"
        max="9999">

    </div>


    <div class="form-row">

      <label>
        附加参数
      </label>

      <input
        id="extra"
        placeholder="例如 no-resolve；没有则留空">

    </div>


    <div class="form-row">

      <label>
        备注
      </label>

      <input
        id="note"
        placeholder="例如：公司系统">

    </div>


    <div class="modal-actions">

      <button
        type="button"
        class="secondary"
        onclick="closeModal()">
        取消
      </button>

      <button
        class="primary">
        保存
      </button>

    </div>

  </form>

</div>


<script>

let rules = [];
let currentTargets = [];
let legacyTargetLabels = {};
let legacyGroupTargets = {};


function addTargetOption(select, value, label, disabled = false) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = label;
  option.disabled = disabled;
  select.appendChild(option);
}


function targetLabel(value) {
  const current = currentTargets.find(item => item.value === effectiveTarget(value));
  if (current) return current.label;
  return "目标已停用";
}


function effectiveTarget(value) {
  return legacyGroupTargets[value] || value;
}


function populateGroupStats() {
  const stats = document.getElementById("stats");
  for (const card of stats.querySelectorAll(".group-stat")) card.remove();
  for (const item of currentTargets.filter(item => item.value !== "DIRECT")) {
    const card = document.createElement("div");
    card.className = "stat group-stat";
    card.dataset.groupTarget = item.value;
    const label = document.createElement("div");
    label.className = "stat-label";
    label.textContent = item.label;
    const value = document.createElement("div");
    value.className = "stat-value";
    value.textContent = "0";
    card.append(label, value);
    stats.appendChild(card);
  }
}


function populateTargetMenus() {
  const filter = document.getElementById("targetFilter");
  const selectedFilter = filter.value;
  filter.replaceChildren();
  addTargetOption(filter, "", "全部出口");

  const select = document.getElementById("target");
  select.replaceChildren();
  for (const item of currentTargets) {
    addTargetOption(filter, item.value, item.label);
    addTargetOption(select, item.value, item.label);
  }

  // The filter lists only current subscription groups. Existing rules with
  // legacy targets still appear under "全部出口" and remain safely editable.
  filter.value = selectedFilter;
}


async function loadTargets() {
  const response = await fetch("./api/targets", {cache: "no-store"});
  if (!response.ok) throw new Error(`出口分组加载失败：HTTP ${response.status}`);
  const data = await response.json();
  currentTargets = data.targets;
  legacyTargetLabels = data.legacy_labels || {};
  legacyGroupTargets = data.legacy_group_targets || {};
  document.getElementById("subtitle").textContent =
    `中国大陆直连 / ${currentTargets.filter(item => item.value !== "DIRECT")
      .map(item => item.label).join(" / ")}`;
  populateGroupStats();
  populateTargetMenus();
}


async function loadRules() {

  await loadTargets();

  const res =
    await fetch("./api/rules", {cache: "no-store"});

  if (!res.ok) throw new Error(`规则加载失败：HTTP ${res.status}`);

  const data =
    await res.json();

  rules =
    data.rules || [];

  populateTargetMenus();
  render();
}


function render() {

  const search =
    document
      .getElementById("search")
      .value
      .toLowerCase();

  const target =
    document
      .getElementById("targetFilter")
      .value;

  const filtered =
    rules
      .filter(r => {

        if (
          target &&
          effectiveTarget(r.target) !== target
        ) {
          return false;
        }

        const text =
          `${r.value} ${r.note || ""}`
            .toLowerCase();

        return text.includes(search);
      })
      .sort(
        (a,b) =>
          Number(a.priority || 100)
          -
          Number(b.priority || 100)
      );


  const body =
    document.getElementById("rows");

  body.innerHTML = "";


  for (const r of filtered) {

    const tr =
      document.createElement("tr");


    tr.innerHTML = `

      <td>
        <input
          class="switch"
          type="checkbox"
          ${r.enabled ? "checked" : ""}
          onchange="toggleRule(
            '${r.id}',
            this.checked
          )">
      </td>

      <td>
        ${r.priority}
      </td>

      <td>
        <span class="tag">
          ${r.type}
        </span>
      </td>

      <td class="value">
        ${escapeHtml(r.value)}
      </td>

      <td
        class="${r.target === "DIRECT" ? "target-DIRECT" : "target-Proxy"}">
        ${escapeHtml(targetLabel(r.target))}
      </td>

      <td>
        ${escapeHtml(r.note || "")}
      </td>

      <td>

        <div class="row-actions">

          <button
            class="secondary"
            onclick="editRule('${r.id}')">
            编辑
          </button>

          <button
            class="danger"
            onclick="deleteRule('${r.id}')">
            删除
          </button>

        </div>

      </td>
    `;

    body.appendChild(tr);
  }


  document
    .getElementById("empty")
    .style.display =
      filtered.length
        ? "none"
        : "block";


  document
    .getElementById("total")
    .textContent =
      rules.length;

  document
    .getElementById("direct")
    .textContent =
      rules.filter(
        r =>
          r.target === "DIRECT"
      ).length;

  for (const card of document.querySelectorAll(".group-stat")) {
    const group = card.dataset.groupTarget;
    card.querySelector(".stat-value").textContent = rules.filter(
      r => effectiveTarget(r.target) === group
    ).length;
  }
}


function openAdd() {

  populateTargetMenus();

  document
    .getElementById("modalTitle")
    .textContent =
      "新增规则";

  ruleId.value = "";

  matchType.value =
    "DOMAIN-SUFFIX";

  ruleValue.value = "";

  target.value =
    "DIRECT";

  priority.value =
    100;

  extra.value = "";

  note.value = "";

  modalBg.style.display =
    "flex";
}


function editRule(id) {

  const r =
    rules.find(
      x => x.id === id
    );

  if (!r) return;

  populateTargetMenus();
  const selectedTarget = effectiveTarget(r.target);
  const currentTarget = currentTargets.some(item => item.value === selectedTarget);
  if (!currentTarget) {
    addTargetOption(target, "", "目标已停用", true);
  }

  modalTitle.textContent =
    "编辑规则";

  ruleId.value =
    r.id;

  matchType.value =
    r.type;

  ruleValue.value =
    r.value;

  target.value =
    currentTarget ? selectedTarget : "";

  priority.value =
    r.priority;

  extra.value =
    r.extra || "";

  note.value =
    r.note || "";

  modalBg.style.display =
    "flex";
}


function closeModal() {

  modalBg.style.display =
    "none";
}


async function saveRule(event) {

  event.preventDefault();

  const existing = rules.find(rule => rule.id === ruleId.value);

  const payload = {

    id:
      ruleId.value || null,

    type:
      matchType.value,

    value:
      ruleValue.value.trim(),

    target:
      target.value,

    priority:
      Number(priority.value),

    extra:
      extra.value.trim(),

    note:
      note.value.trim(),

    enabled:
      existing ? existing.enabled : true
  };

  try {
    await postRule(payload);
  } catch (error) {
    alert(`保存失败：${error.message}`);
    return;
  }
  closeModal();
  try {
    await loadRules();
  } catch (error) {
    alert(`已保存，但列表刷新失败：${error.message}`);
  }
}


async function postRule(payload) {
  const response = await fetch("./api/rules", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(payload)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || !result.ok) {
    throw new Error(result.error || `HTTP ${response.status}`);
  }
  return result;
}


async function deleteRule(id) {

  if (
    !confirm(
      "确定删除这条规则？"
    )
  ) {
    return;
  }


  await fetch(
    "./api/rules/" + id,
    {
      method: "DELETE"
    }
  );

  await loadRules();
}


async function toggleRule(
  id,
  enabled
) {

  const r =
    rules.find(
      x => x.id === id
    );

  if (!r) return;

  try {
    await postRule({...r, enabled});
  } catch (error) {
    render();
    alert(`更新失败：${error.message}`);
    return;
  }
  try {
    await loadRules();
  } catch (error) {
    alert(`已更新，但列表刷新失败：${error.message}`);
  }
}


function exportRules() {

  const text =
    JSON.stringify(
      {rules},
      null,
      2
    );

  const blob =
    new Blob(
      [text],
      {
        type:
          "application/json"
      }
    );

  const a =
    document.createElement("a");

  a.href =
    URL.createObjectURL(blob);

  a.download =
    "route_rules.json";

  a.click();

  URL.revokeObjectURL(
    a.href
  );
}


function escapeHtml(value) {

  return String(value || "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;");
}


async function initialize() {
  try {
    await loadRules();
  } catch (error) {
    alert(error.message);
  }
}

initialize();

</script>

</body>
</html>
'''

SERVER_ROUTING_PANEL = r'''
<script>
(() => {
  async function loadServerRouting(){
    const response=await fetch('./api/server-routing',{cache:'no-store'});
    if(!response.ok)return;
    const data=await response.json();if(!data.enabled)return;
    const panel=document.createElement('section');panel.id='server-routing-inventory';
    panel.style.cssText='margin:24px auto;padding:20px;max-width:1200px;border:1px solid #334155;border-radius:12px;overflow:auto';
    const title=document.createElement('h2');title.textContent='服务器与链路测试';panel.append(title);
    const groups=document.createElement('p');groups.textContent=data.groups.join(' / ');panel.append(groups);
    const table=document.createElement('table');table.style.cssText='width:100%;text-align:left;border-collapse:collapse';
    const head=document.createElement('tr');
    for(const value of ['服务器','网络','套餐','流量 / 速率','续费日','状态']){
      const cell=document.createElement('th');cell.textContent=value;cell.style.padding='10px';head.append(cell);
    }table.append(head);
    for(const row of data.servers){
      const tr=document.createElement('tr');
      const due=row.due_month_day?('每年 '+row.due_month_day):row.due_day?('每月 '+row.due_day+' 日'):'未落实';
      const values=[row.display_name,row.description,(row.currency==='CNY'?'¥':'US$')+row.amount+(row.billing==='annual'?'/年':'/月'),
        (row.quota||'未公布')+' / '+(row.speed||'未公布'),due,({active:'统计中',archived:'已归档',pending:'未接入'})[row.status]||'待核查'];
      for(const value of values){const cell=document.createElement('td');cell.textContent=value;cell.style.padding='10px';tr.append(cell)}
      table.append(tr);
    }panel.append(table);
    const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='各链路的独立 IP 测试网站';details.append(summary);
    for(const [id,item] of Object.entries(data.ip_tests||{})){
      const row=document.createElement('p');const name=document.createElement('span');name.textContent=(data.route_labels[id]||id)+'：';
      const link=document.createElement('a');link.textContent=item.url;link.href=item.url;link.target='_blank';link.rel='noopener noreferrer';row.append(name,link);details.append(row);
    }panel.append(details);
    const app=document.querySelector('main')||document.body;app.append(panel);
  }
  loadServerRouting().catch(()=>{});
})();
</script>
'''
HTML=HTML.replace('</body>',SERVER_ROUTING_PANEL+'</body>',1)


@APP.get("/")
def index():
    return Response(
        HTML,
        mimetype="text/html",
    )


@APP.get("/api/rules")
def get_rules():
    return jsonify(
        display_data(load_data(), target_contract())
    )


@APP.get("/api/targets")
def get_targets():
    contract = target_contract()
    return jsonify({
        "targets": [
            {"value": value, "label": label}
            for value, label in contract['targets'].items()
        ],
        "legacy_labels": contract['legacy_labels'],
        "legacy_group_targets": contract['legacy_group_targets'],
        "summary_targets": contract['summary_targets'],
        "plan": contract['plan'],
        "target_catalog_version": RULE_UI_VERSION,
    })

@APP.get('/api/server-routing')
def get_server_routing():
    from routing_rule_catalog import server_metadata
    try:
        return jsonify(server_metadata())
    except (OSError, ValueError, KeyError, TypeError):
        return jsonify(error='server_routing_metadata_unavailable'),503


@APP.post("/api/rules")
def save_rule():

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    rule_type = str(
        payload.get(
            "type",
            ""
        )
    ).strip()

    value = str(
        payload.get(
            "value",
            ""
        )
    ).strip()

    target = str(
        payload.get(
            "target",
            ""
        )
    ).strip()


    if rule_type not in MATCH_TYPES:
        return jsonify({
            "error":
              "无效匹配类型"
        }), 400


    data = load_data()
    rules = data["rules"]
    requested_id = payload.get("id")
    existing = next(
        (
            rule for rule in rules
            if isinstance(rule, dict) and rule.get("id") == requested_id
        ),
        None,
    ) if requested_id else None

    # GET exposes canonical display names; equivalent edits preserve the raw
    # historical target. Only an explicit different current target retargets.
    contract = target_contract()
    existing_raw = existing.get('target') if existing is not None else None
    existing_current = canonical_target(existing_raw, contract)
    retain_retired = (existing is not None and existing_current is None and
                      target in ('', existing_raw))
    if target not in contract['targets'] and not (
        existing is not None and existing_raw == target
    ) and not retain_retired:
        return jsonify({
            "error":
              "无效出口"
        }), 400

    if retain_retired and not existing.get('enabled', False) and payload.get('enabled', True):
        return jsonify({'error': '请先选择有效出口'}), 400
    if retain_retired or (existing is not None and target == existing_current):
        target = existing_raw


    if not value:
        return jsonify({
            "error":
              "规则内容不能为空"
        }), 400


    try:
        priority = int(
            payload.get(
                "priority",
                100
            )
        )

    except Exception:
        priority = 100


    priority = max(
        1,
        min(
            priority,
            9999
        )
    )


    rule_id = (
        requested_id
        or str(uuid.uuid4())
    )


    new_rule = {
        **copy.deepcopy(existing or {}),

        "id":
          rule_id,

        "type":
          rule_type,

        "value":
          value,

        "target":
          target,

        "priority":
          priority,

        "enabled":
          bool(
            payload.get(
                "enabled",
                True
            )
          ),

        "extra":
          str(
            payload.get(
                "extra",
                ""
            )
          ).strip(),

        "note":
          str(
            payload.get(
                "note",
                ""
            )
          ).strip()
    }


    replaced = False


    for i, rule in enumerate(
        rules
    ):

        if rule.get("id") == rule_id:

            rules[i] = new_rule

            replaced = True

            break


    if not replaced:
        rules.append(
            new_rule
        )


    save_data(data)


    return jsonify({
        "ok": True,
        "rule": display_data({'rules': [new_rule]}, contract)['rules'][0]
    })


@APP.delete(
    "/api/rules/<rule_id>"
)
def delete_rule(rule_id):

    data = load_data()

    data["rules"] = [
        r
        for r in data["rules"]
        if r.get("id")
        != rule_id
    ]

    save_data(data)

    return jsonify({
        "ok": True
    })


if __name__ == "__main__":

    APP.run(
        host="127.0.0.1",
        port=18081,
        debug=False,
    )

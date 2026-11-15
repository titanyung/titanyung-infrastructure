document.addEventListener('submit', event => {
  const message = event.target.getAttribute('data-confirm');
  if (message && !window.confirm(message)) event.preventDefault();
  if (event.target.action.endsWith('/logout')) sessionStorage.removeItem('ledger-draft-v1');
});

const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
async function postJson(url, payload) {
  const response = await fetch(url, {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
    body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`服务返回 ${response.status}`);
  return response.json();
}

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js', {scope: '/'}).catch(() => {}));
}

const quickToggle = document.querySelector('.quick-toggle');
const quickPanel = document.querySelector('#quick-add-panel');
if (quickToggle && quickPanel) {
  quickToggle.addEventListener('click', () => {
    quickPanel.hidden = !quickPanel.hidden;
    quickToggle.setAttribute('aria-expanded', String(!quickPanel.hidden));
    if (!quickPanel.hidden) quickPanel.querySelector('input[name="amount"]')?.focus();
  });
  quickPanel.querySelector('input[name="return_to"]').value = location.pathname + location.search;
}

for (const tagInput of document.querySelectorAll('[data-tag-input]')) {
  for (const choice of tagInput.parentElement.querySelectorAll('[data-tag-choice]')) {
    choice.addEventListener('click', () => {
      const selected = tagInput.value.split(/[,，;；\s]+/).filter(Boolean);
      const name = choice.dataset.tagChoice;
      if (!selected.some(value => value.toLocaleLowerCase() === name.toLocaleLowerCase())) selected.push(name);
      tagInput.value = selected.join(' ') + ' ';
      choice.classList.add('selected');
      tagInput.dispatchEvent(new Event('input', {bubbles: true}));
      tagInput.focus();
    });
  }
}

const draftKey = 'ledger-draft-v1';
function editableForms() {
  return [...document.querySelectorAll('main form, .quick-panel form')].filter(form =>
    !form.action.endsWith('/logout') &&
    [...form.elements].some(field => field.name && field.name !== 'code' &&
      !['hidden', 'password', 'submit'].includes(field.type)));
}
function saveDraft() {
  const forms = editableForms().map((form, index) => ({
    index, action: form.getAttribute('action') || '',
    fields: [...form.elements].filter(field => field.name && field.name !== 'code' &&
      !['hidden', 'password', 'submit'].includes(field.type))
      .map(field => ({name: field.name, value: field.value, checked: field.checked, type: field.type}))
  }));
  sessionStorage.setItem(draftKey, JSON.stringify({url: location.pathname + location.search, forms,
    quickOpen: Boolean(quickPanel && !quickPanel.hidden), at: Date.now()}));
}
function restoreDraft() {
  let draft;
  try { draft = JSON.parse(sessionStorage.getItem(draftKey) || 'null'); } catch { draft = null; }
  if (!draft || draft.url !== location.pathname + location.search || Date.now() - draft.at > 12 * 3600000) return;
  const forms = editableForms();
  for (const entry of draft.forms) {
    const form = forms[entry.index];
    if (!form || (form.getAttribute('action') || '') !== entry.action) continue;
    for (const field of entry.fields) {
      const target = [...form.elements].find(element => element.name === field.name && element.type === field.type);
      if (!target) continue;
      if (field.type === 'checkbox' || field.type === 'radio') target.checked = field.checked;
      else target.value = field.value;
      target.dispatchEvent(new Event('input', {bubbles: true}));
    }
  }
  if (draft.quickOpen && quickPanel && quickToggle) {
    quickPanel.hidden = false;
    quickToggle.setAttribute('aria-expanded', 'true');
  }
  sessionStorage.removeItem(draftKey);
}
if (quickPanel) restoreDraft();

if (quickPanel) {
  let lastInteraction = Date.now();
  let lastPing = 0;
  let locking = false;
  function touch() {
    if (locking) return;
    lastInteraction = Date.now();
    if (Date.now() - lastPing > 20000) {
      lastPing = Date.now();
      fetch('/activity', {method: 'POST', credentials: 'same-origin', headers: {'X-CSRF-Token': csrf}})
        .then(response => { if (response.redirected) lockNow(); }).catch(() => {});
    }
  }
  async function lockNow() {
    if (locking) return;
    locking = true;
    saveDraft();
    try {
      const body = new URLSearchParams({csrf_token: csrf, return_to: location.pathname + location.search});
      await fetch('/lock', {method: 'POST', credentials: 'same-origin', body});
    } catch {}
    location.assign('/login');
  }
  for (const eventName of ['pointerdown', 'keydown', 'input', 'scroll']) {
    window.addEventListener(eventName, touch, {passive: true});
  }
  setInterval(() => { if (Date.now() - lastInteraction >= 60000) lockNow(); }, 1000);
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && Date.now() - lastInteraction >= 60000) lockNow();
  });
}

function b64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function binary(value) {
  const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4));
  return Uint8Array.from(raw, char => char.charCodeAt(0));
}
function credentialJson(credential) {
  const result = {id: credential.id, rawId: b64url(credential.rawId), type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(), response: {
      clientDataJSON: b64url(credential.response.clientDataJSON)
    }};
  if (credential.response.attestationObject) {
    result.response.attestationObject = b64url(credential.response.attestationObject);
    result.response.transports = credential.response.getTransports?.() || [];
  } else {
    result.response.authenticatorData = b64url(credential.response.authenticatorData);
    result.response.signature = b64url(credential.response.signature);
    result.response.userHandle = credential.response.userHandle ? b64url(credential.response.userHandle) : null;
  }
  return result;
}
const registerButton = document.querySelector('#register-passkey');
if (registerButton) registerButton.addEventListener('click', async () => {
  const status = document.querySelector('#passkey-status');
  registerButton.disabled = true;
  try {
    if (!window.PublicKeyCredential || !await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
      throw new Error('此设备或浏览器暂不支持设备指纹凭证');
    const password = document.querySelector('#passkey-current-password').value;
    if (!password) throw new Error('请先输入当前密码');
    const options = await postJson('/passkeys/register/options', {password});
    options.challenge = binary(options.challenge);
    options.user.id = binary(options.user.id);
    for (const item of options.excludeCredentials || []) item.id = binary(item.id);
    const credential = await navigator.credentials.create({publicKey: options});
    await postJson('/passkeys/register/verify', credentialJson(credential));
    document.querySelector('#passkey-current-password').value = '';
    status.textContent = '本设备已启用安全凭证。下次锁屏可使用手机验证解锁。';
  } catch (error) { status.textContent = `启用失败：${error.message}`; }
  finally { registerButton.disabled = false; }
});
const unlockButton = document.querySelector('[data-passkey-unlock]');
if (unlockButton) unlockButton.addEventListener('click', async () => {
  unlockButton.disabled = true;
  try {
    const options = await postJson('/passkeys/auth/options', {});
    options.challenge = binary(options.challenge);
    for (const item of options.allowCredentials || []) item.id = binary(item.id);
    const credential = await navigator.credentials.get({publicKey: options});
    const result = await postJson('/passkeys/auth/verify', credentialJson(credential));
    location.assign(result.next);
  } catch (error) { window.alert(`设备解锁失败：${error.message}`); unlockButton.disabled = false; }
});

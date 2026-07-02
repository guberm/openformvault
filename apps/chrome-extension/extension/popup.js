const $ = id => document.getElementById(id);
const status = $('status');
const syncState = $('sync-state');
const authSection = $('auth');
const vaultSection = $('vault');
const itemsEl = $('items');
const revisionLabel = $('revision-label');
const visibleSecrets = new Set();
let activeFilter = 'login';
let authMode = 'login';

let session = { serverUrl: '', username: '', token: '', masterPassword: '', vault: { items: [] }, revision: 0 };
let autoSyncTimer = null;

function setStatus(message) { status.textContent = message; }
function setSyncState(message, kind = '') { syncState.textContent = message; syncState.className = `sync-pill ${kind}`.trim(); }
function normalizeServerUrl() { return $('server-url').value.trim().replace(/\/+$/, ''); }
function uuid() { return crypto.randomUUID(); }
function encUtf8(value) { return new TextEncoder().encode(value); }
function decUtf8(value) { return new TextDecoder().decode(value); }
function b64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function unb64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function escapeHtml(value) { return String(value ?? '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c])); }
function normalizeItem(item) {
  return {
    id: item.id || uuid(),
    type: item.type || 'login',
    title: item.title || item.name || item.url || item.username || 'Untitled login',
    url: item.url || item.uri || '',
    username: item.username || item.login || '',
    password: item.password || '',
    otpSecret: item.otpSecret || item.totp || item.otp || '',
    notes: item.notes || item.note || '',
    passkey: item.passkey || null,
    folder: item.folder || '',
    updatedAt: item.updatedAt || new Date().toISOString()
  };
}

async function deriveKey(password, salt, usages = ['encrypt', 'decrypt']) {
  const material = await crypto.subtle.importKey('raw', encUtf8(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 310000 }, material, { name: 'AES-GCM', length: 256 }, false, usages);
}

async function encryptVault(vault, password, existingSalt) {
  const salt = existingSalt ? unb64(existingSalt) : crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const normalizedVault = { items: (vault.items || []).map(normalizeItem) };
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, encUtf8(JSON.stringify(normalizedVault)));
  return { ciphertext: b64(ciphertext), nonce: b64(nonce), salt: b64(salt), algorithm: 'AES-GCM', kdf: 'PBKDF2-SHA256-310000' };
}

async function decryptVault(snapshot, password) {
  const key = await deriveKey(password, unb64(snapshot.salt));
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(snapshot.nonce) }, key, unb64(snapshot.ciphertext));
  const vault = JSON.parse(decUtf8(plaintext));
  return { items: (vault.items || []).map(normalizeItem) };
}

async function api(path, options = {}) {
  const headers = { 'content-type': 'application/json', ...(options.headers ?? {}) };
  if (session.token) headers.authorization = `Bearer ${session.token}`;
  const response = await fetch(`${session.serverUrl}${path}`, { ...options, headers, cache: 'no-store' });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(body?.code ?? body?.message ?? `HTTP ${response.status}`);
  return body;
}

async function saveLocalSession(extra = {}) {
  await chrome.storage.local.set({ serverUrl: session.serverUrl, username: session.username, token: session.token, revision: session.revision, ...extra });
}

async function loadLocalSession() {
  const stored = await chrome.storage.local.get(['serverUrl', 'username', 'token', 'revision', 'themeMode']);
  if (stored.serverUrl) $('server-url').value = stored.serverUrl;
  if (stored.username) $('username').value = stored.username;
  session.serverUrl = stored.serverUrl ?? normalizeServerUrl();
  session.username = stored.username ?? '';
  session.token = stored.token ?? '';
  session.revision = stored.revision ?? 0;
  if (stored.themeMode) $('theme-mode').value = stored.themeMode;
  applyTheme($('theme-mode')?.value || stored.themeMode || 'System');
  updateRevision();
  setSyncState(session.token ? 'signed in' : 'offline', session.token ? 'ok' : '');
  await renderPendingSaveCandidate();
}


function applyTheme(mode) {
  const effective = mode === 'System' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'Dark' : 'Light') : mode;
  document.body.dataset.theme = effective;
}
async function saveTheme() {
  const mode = $('theme-mode').value;
  await chrome.storage.local.set({ themeMode: mode });
  applyTheme(mode);
  setStatus(`Theme set to ${mode}.`);
}
function securityReport() {
  const items = session.vault.items.map(normalizeItem);
  const weak = items.filter(x => (x.password || '').length < 12).length;
  const missingOtp = items.filter(x => !x.otpSecret).length;
  const httpOnly = items.filter(x => String(x.url || '').toLowerCase().startsWith('http://')).length;
  const counts = new Map();
  for (const item of items) if (item.password) counts.set(item.password, (counts.get(item.password) || 0) + 1);
  const reused = [...counts.values()].filter(x => x > 1).reduce((a, b) => a + b, 0);
  const duplicateKeys = new Set();
  let duplicateCredentials = 0;
  for (const item of items) {
    const key = `${item.url}|${item.username}`.toLowerCase();
    if (duplicateKeys.has(key)) duplicateCredentials++; else duplicateKeys.add(key);
  }
  $('security-result').textContent = [`Items: ${items.length}`, `Weak passwords: ${weak}`, `Reused passwords: ${reused}`, `HTTP-only sites: ${httpOnly}`, `Missing OTP: ${missingOtp}`, `Duplicate URL+username: ${duplicateCredentials}`].join('\n');
}

function updateRevision() { revisionLabel.textContent = session.revision ? `Synced revision ${session.revision}` : 'Ready to sync'; }
function showVault() { authSection.hidden = true; vaultSection.hidden = false; $('item-form').hidden = true; $('settings-panel').hidden = true; updateRevision(); renderItems(); }
function showAuth() { vaultSection.hidden = true; authSection.hidden = false; }
function setAuthMode(mode) {
  authMode = mode;
  const register = mode === 'register';
  $('auth-title').textContent = register ? 'Create your OpenFormVault account' : 'Sign in to OpenFormVault';
  $('confirm-password-row').hidden = !register;
  $('login').hidden = register;
  $('back-to-login').hidden = !register;
  $('register').textContent = register ? 'Create account' : 'Create account';
  $('password').autocomplete = register ? 'new-password' : 'current-password';
}
function togglePassword(inputId, buttonId) { const input = $(inputId); input.type = input.type === 'password' ? 'text' : 'password'; $(buttonId).textContent = input.type === 'password' ? '👁' : '🙈'; }

function matchesFilter(item) {
  if (activeFilter === 'otp') return Boolean(item.otpSecret);
  if (activeFilter === 'passkey') return Boolean(item.passkey?.credentialId || item.passkey?.rpId);
  return true;
}

function matchesSearch(item) {
  const q = ($('vault-search')?.value || '').trim().toLowerCase();
  if (!q) return true;
  return [item.title, item.url, item.username, item.folder, item.notes].some(value => String(value || '').toLowerCase().includes(q));
}

function renderItems() {
  itemsEl.textContent = '';
  updateRevision();
  const visibleItems = session.vault.items.map(normalizeItem).filter(item => matchesFilter(item) && matchesSearch(item));
  if (visibleItems.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = session.vault.items.length === 0 ? 'No logins yet. Add your first saved login.' : 'No matching items.';
    itemsEl.append(empty);
    return;
  }
  for (const item of visibleItems) {
    const div = document.createElement('div');
    div.className = 'item';
    const secretVisible = visibleSecrets.has(item.id);
    const otpBadge = item.otpSecret ? '<span class="badge">OTP</span>' : '';
    const passkeyBadge = item.passkey?.credentialId ? '<span class="badge">Passkey</span>' : '';
    div.innerHTML = `
      <div class="item-head">
        <div>
          <strong>${escapeHtml(item.title)}</strong>
          <small>${escapeHtml(item.url)} ${escapeHtml(item.username)}</small>
          <div>${otpBadge}${passkeyBadge}${item.folder ? `<span class="badge">${escapeHtml(item.folder)}</span>` : ''}</div>
        </div>
      </div>
      <div class="secret" hidden></div>
      <div class="item-actions"></div>`;
    const secret = div.querySelector('.secret');
    secret.hidden = !secretVisible;
    secret.textContent = secretVisible ? `Password: ${item.password || '(empty)'}` : '';
    const row = div.querySelector('.item-actions');
    row.append(
      actionButton('Fill', () => fillLogin(item), 'primary small'),
      actionButton(secretVisible ? 'Hide' : 'View', () => { secretVisible ? visibleSecrets.delete(item.id) : visibleSecrets.add(item.id); renderItems(); }, 'secondary small'),
      actionButton('Edit', () => startEdit(item), 'ghost small'),
      actionButton('Delete', () => deleteItem(item), 'danger small')
    );
    if (item.otpSecret) row.append(actionButton('Copy OTP', async () => copyOtp(item), 'secondary small'));
    itemsEl.append(div);
  }
}

function actionButton(text, handler, className = '') {
  const button = document.createElement('button');
  button.textContent = text;
  if (className) button.className = className;
  button.addEventListener('click', handler);
  return button;
}

async function pullVault() {
  try {
    const snapshot = await api('/v1/vault/snapshot');
    session.vault = await decryptVault(snapshot, session.masterPassword);
    session.revision = snapshot.revision;
    await saveLocalSession({ encryptedSnapshot: snapshot });
    showVault();
    setSyncState('synced', 'ok');
    setStatus(`Pulled revision ${session.revision}.`);
  } catch (error) {
    if (String(error.message).includes('vault_snapshot_not_found')) {
      session.vault = { items: [] };
      session.revision = 0;
      showVault();
      setStatus('No remote vault yet. Add a login; changes auto-sync.');
      setSyncState('empty vault', 'ok');
      return;
    }
    throw error;
  }
}

async function pushVault() {
  const existing = await chrome.storage.local.get(['vaultSalt']);
  const encrypted = await encryptVault(session.vault, session.masterPassword, existing.vaultSalt);
  await chrome.storage.local.set({ vaultSalt: encrypted.salt, encryptedSnapshot: { ...encrypted, revision: session.revision } });
  const result = await api('/v1/vault/snapshot', { method: 'PUT', body: JSON.stringify({ ...encrypted, baseRevision: session.revision || null }) });
  session.revision = result.revision;
  await saveLocalSession({ vaultSalt: encrypted.salt });
  updateRevision();
  setSyncState('synced', 'ok');
  setStatus(`Pushed revision ${session.revision}.`);
}

async function persistAndAutoSync(message = 'Saved. Auto-syncing…') {
  renderItems();
  setStatus(message);
  if (!session.token || !session.masterPassword) { setSyncState('local only', 'error'); return; }
  clearTimeout(autoSyncTimer);
  setSyncState('sync pending', 'busy');
  autoSyncTimer = setTimeout(async () => {
    try { await pushVault(); }
    catch (error) {
      setSyncState('sync error', 'error');
      setStatus(`Auto-sync failed: ${error.message}. Pull latest if this is a conflict.`);
    }
  }, 300);
}

async function auth(mode) {
  session.serverUrl = normalizeServerUrl();
  session.username = $('username').value.trim();
  session.masterPassword = $('password').value;
  if (mode === 'register' && session.masterPassword !== $('confirm-password').value) throw new Error('Passwords do not match.');
  const result = await api(mode === 'register' ? '/v1/users/register' : '/v1/session', {
    method: 'POST',
    body: JSON.stringify({ username: session.username, password: session.masterPassword })
  });
  session.token = result.token;
  await saveLocalSession();
  await pullVault();
}

async function checkHealth() {
  session.serverUrl = normalizeServerUrl();
  const response = await fetch(`${session.serverUrl}/health`, { cache: 'no-store' });
  if (!response.ok) throw new Error(`Health HTTP ${response.status}`);
  const health = await response.json();
  setStatus(`${health.product ?? 'Server'} is online.`);
}

async function fillLogin(item) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await chrome.tabs.sendMessage(tab.id, { type: 'OFV_FILL_LOGIN', username: item.username, password: item.password });
  setStatus('Fill request sent to current tab.');
}

async function renderPendingSaveCandidate() {
  const { pendingSaveCandidate } = await chrome.storage.local.get(['pendingSaveCandidate']);
  const section = $('detected-login');
  if (!pendingSaveCandidate) { section.hidden = true; return; }
  section.hidden = false;
  $('detected-login-text').textContent = `${pendingSaveCandidate.title || pendingSaveCandidate.tabTitle || 'Detected login'} — ${pendingSaveCandidate.url || pendingSaveCandidate.tabUrl || ''} — ${pendingSaveCandidate.username || '(no username)'}`;
}

async function savePendingCandidate() {
  const { pendingSaveCandidate } = await chrome.storage.local.get(['pendingSaveCandidate']);
  if (!pendingSaveCandidate) return;
  session.vault.items.push(normalizeItem({
    title: pendingSaveCandidate.title || pendingSaveCandidate.tabTitle,
    url: pendingSaveCandidate.url || pendingSaveCandidate.tabUrl,
    username: pendingSaveCandidate.username,
    password: pendingSaveCandidate.password,
    notes: `Saved from browser form on ${pendingSaveCandidate.storedAt || new Date().toISOString()}`
  }));
  await chrome.storage.local.remove(['pendingSaveCandidate']);
  await renderPendingSaveCandidate();
  await persistAndAutoSync('Detected login saved. Auto-syncing…');
}

async function dismissPendingCandidate() {
  await chrome.storage.local.remove(['pendingSaveCandidate']);
  await renderPendingSaveCandidate();
  setStatus('Detected login dismissed.');
}

function readForm() {
  const passkey = $('item-passkey-rp-id').value.trim() || $('item-passkey-credential-id').value.trim()
    ? { rpId: $('item-passkey-rp-id').value.trim(), credentialId: $('item-passkey-credential-id').value.trim(), userHandle: '', transports: [] }
    : null;
  return normalizeItem({
    id: $('editing-id').value || uuid(),
    title: $('item-title').value.trim(),
    url: $('item-url').value.trim(),
    username: $('item-username').value.trim(),
    password: $('item-password').value,
    otpSecret: $('item-otp-secret').value.trim().replace(/\s+/g, ''),
    passkey,
    notes: $('item-notes').value,
    updatedAt: new Date().toISOString()
  });
}

function clearForm() {
  $('editing-id').value = '';
  $('item-title').value = $('item-url').value = $('item-username').value = $('item-password').value = $('item-otp-secret').value = $('item-passkey-rp-id').value = $('item-passkey-credential-id').value = $('item-notes').value = '';
  $('form-title').textContent = 'Add login';
  $('save-login').textContent = 'Save';
  $('cancel-edit').hidden = true;
  $('item-form').hidden = true;
}

function saveLogin() {
  const item = readForm();
  const idx = session.vault.items.findIndex(x => x.id === item.id);
  if (idx >= 0) session.vault.items[idx] = item;
  else session.vault.items.push(item);
  clearForm();
  persistAndAutoSync(idx >= 0 ? 'Login updated. Auto-syncing…' : 'Login saved. Auto-syncing…');
}

function startEdit(item) {
  $('editing-id').value = item.id;
  $('item-title').value = item.title || '';
  $('item-url').value = item.url || '';
  $('item-username').value = item.username || '';
  $('item-password').value = item.password || '';
  $('item-otp-secret').value = item.otpSecret || '';
  $('item-passkey-rp-id').value = item.passkey?.rpId || '';
  $('item-passkey-credential-id').value = item.passkey?.credentialId || '';
  $('item-notes').value = item.notes || '';
  $('form-title').textContent = 'Edit login';
  $('save-login').textContent = 'Update';
  $('cancel-edit').hidden = false;
  $('item-form').hidden = false;
  $('settings-panel').hidden = true;
  setStatus(`Editing ${item.title}.`);
}

function deleteItem(item) {
  if (!confirm(`Delete ${item.title || item.username || item.url}?`)) return;
  session.vault.items = session.vault.items.filter(x => x.id !== item.id);
  visibleSecrets.delete(item.id);
  persistAndAutoSync('Login deleted. Auto-syncing…');
}

function generatePassword() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+';
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  $('item-password').value = [...bytes].map(b => alphabet[b % alphabet.length]).join('');
}

function parseCsv(text) {
  const rows = [];
  let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (quoted && c === '"' && n === '"') { cell += '"'; i++; }
    else if (c === '"') quoted = !quoted;
    else if (!quoted && c === ',') { row.push(cell); cell = ''; }
    else if (!quoted && (c === '\n' || c === '\r')) {
      if (c === '\r' && n === '\n') i++;
      row.push(cell); cell = '';
      if (row.some(x => x.trim())) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some(x => x.trim())) rows.push(row);
  return rows;
}
function pick(record, names) { for (const name of names) { const value = record[name.toLowerCase()]; if (value) return value; } return ''; }
function applyRoboFormFieldFallback(record, item) {
  const fieldCells = [pick(record, ['rffieldsv2', 'rf fields v2', 'roboform fields']), ...(record.__extra || [])].filter(x => x && x.trim());
  for (let i = 0; i + 4 < fieldCells.length; i += 5) {
    const label = fieldCells[i].toLowerCase();
    const htmlName = fieldCells[i + 2].toLowerCase();
    const type = fieldCells[i + 3].toLowerCase();
    const value = fieldCells[i + 4].trim();
    const key = `${label} ${htmlName}`;
    if (!value) continue;
    if (!item.password && (type === 'pwd' || key.includes('pass'))) item.password = value;
    else if (!item.otpSecret && /otp|totp|authenticator|verification/.test(key)) item.otpSecret = value.replace(/\s+/g, '');
    else if (!item.username && (/(login|user|email)/.test(key) || type === 'email' || type === 'txt')) item.username = value;
  }
  return item;
}
function importedItems() {
  const rows = parseCsv($('import-text').value.trim());
  if (rows.length < 2) return [];
  const headers = rows[0].map(h => h.trim().toLowerCase());
  return rows.slice(1).map(row => {
    const record = Object.fromEntries(headers.map((h, i) => [h, row[i] || '']));
    record.__extra = row.slice(headers.length).filter(x => x && x.trim());
    const noteParts = [pick(record, ['note', 'notes', 'memo']), pick(record, ['rffieldsv2', 'rf fields v2', 'roboform fields']), record.__extra.join('\n')].filter(x => x && x.trim());
    return applyRoboFormFieldFallback(record, normalizeItem({
      title: pick(record, ['name', 'title', 'login name', 'caption']),
      url: pick(record, ['url', 'matchurl', 'match url', 'web site', 'website', 'site']),
      username: pick(record, ['login', 'username', 'user name', 'userid', 'user id']),
      password: pick(record, ['password', 'pwd', 'pass']),
      notes: noteParts.join('\n\n'),
      folder: pick(record, ['folder', 'path', 'group']),
      otpSecret: pick(record, ['totp', 'otp', 'otp secret', 'authenticator key'])
    }));
  }).filter(item => item.title || item.url || item.username || item.password);
}
function previewImport() {
  const items = importedItems();
  $('import-result').textContent = `${items.length} importable item(s).\n` + items.slice(0, 8).map(x => `- ${x.title} ${x.url} ${x.username}`).join('\n');
}
async function commitImport() {
  const items = importedItems();
  const existing = new Set(session.vault.items.map(x => `${x.url}|${x.username}|${x.title}`));
  const fresh = items.filter(x => !existing.has(`${x.url}|${x.username}|${x.title}`));
  session.vault.items.push(...fresh);
  $('import-result').textContent = `Imported ${fresh.length}; skipped ${items.length - fresh.length} duplicate(s).`;
  await persistAndAutoSync('RoboForm/CSV import saved. Auto-syncing…');
}

function base32ToBytes(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = '', out = [];
  for (const char of clean) {
    const val = alphabet.indexOf(char);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, '0');
    while (bits.length >= 8) { out.push(parseInt(bits.slice(0, 8), 2)); bits = bits.slice(8); }
  }
  return new Uint8Array(out);
}
async function totp(secret, step = 30, digits = 6) {
  const counter = Math.floor(Date.now() / 1000 / step);
  const msg = new ArrayBuffer(8);
  new DataView(msg).setBigUint64(0, BigInt(counter));
  const key = await crypto.subtle.importKey('raw', base32ToBytes(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const offset = sig[sig.length - 1] & 0xf;
  const code = ((sig[offset] & 0x7f) << 24) | (sig[offset + 1] << 16) | (sig[offset + 2] << 8) | sig[offset + 3];
  return String(code % (10 ** digits)).padStart(digits, '0');
}
async function copyOtp(item) {
  const code = await totp(item.otpSecret);
  await navigator.clipboard.writeText(code);
  setStatus(`OTP copied for ${item.title}: ${code}`);
}

$('health-check').addEventListener('click', () => checkHealth().catch(e => setStatus(e.message)));
$('register').addEventListener('click', () => { if (authMode !== 'register') { setAuthMode('register'); return; } auth('register').catch(e => setStatus(e.message)); });
$('login').addEventListener('click', () => auth('login').catch(e => setStatus(e.message)));
$('back-to-login').addEventListener('click', () => setAuthMode('login'));
$('show-master-password').addEventListener('click', () => togglePassword('password', 'show-master-password'));
$('show-confirm-password').addEventListener('click', () => togglePassword('confirm-password', 'show-confirm-password'));
$('sync-pull').addEventListener('click', () => pullVault().catch(e => { setSyncState('pull error', 'error'); setStatus(e.message); }));
$('sync-push').addEventListener('click', () => pushVault().catch(e => { setSyncState('push error', 'error'); setStatus(e.message); }));
$('lock').addEventListener('click', () => { session.masterPassword = ''; session.token = ''; showAuth(); setStatus('Locked.'); setSyncState('offline'); });
$('theme-mode').addEventListener('change', () => saveTheme().catch(e => setStatus(e.message)));
$('security-report').addEventListener('click', securityReport);
$('save-login').addEventListener('click', saveLogin);
$('cancel-edit').addEventListener('click', clearForm);
$('add-login').addEventListener('click', () => { clearForm(); $('item-form').hidden = false; $('settings-panel').hidden = true; });
$('close-form').addEventListener('click', clearForm);
$('settings-toggle').addEventListener('click', () => { $('settings-panel').hidden = !$('settings-panel').hidden; $('item-form').hidden = true; });
$('close-settings').addEventListener('click', () => { $('settings-panel').hidden = true; });
$('vault-search').addEventListener('input', renderItems);
document.querySelectorAll('.tab').forEach(tab => tab.addEventListener('click', () => {
  activeFilter = tab.dataset.filter || 'login';
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === tab));
  renderItems();
}));
$('generate-password').addEventListener('click', generatePassword);
$('import-file').addEventListener('change', async event => { const file = event.target.files?.[0]; if (file) $('import-text').value = await file.text(); previewImport(); });
$('import-preview').addEventListener('click', previewImport);
$('import-commit').addEventListener('click', () => commitImport().catch(e => setStatus(e.message)));
$('save-detected-login').addEventListener('click', () => savePendingCandidate().catch(e => setStatus(e.message)));
$('dismiss-detected-login').addEventListener('click', () => dismissPendingCandidate().catch(e => setStatus(e.message)));

setAuthMode('login');
await loadLocalSession();

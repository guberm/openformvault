import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { webcrypto } from 'node:crypto';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const chrome = process.env.CHROME || '/usr/bin/google-chrome';
const extensionArg = process.argv.slice(2).find(arg => !arg.startsWith('--'));
const extensionDir = path.resolve(extensionArg ?? path.join(root, 'dist', 'openformvault-chrome-extension'));
const runFlow = process.argv.includes('--flow') || process.env.OFV_POPUP_E2E === '1';
const serverUrl = (process.env.OFV_SERVER_URL || 'https://openformvault.guber.dev').replace(/\/+$/, '');
const port = Number(process.env.CDP_PORT || 9333);
const username = `cdp-${Date.now()}-${Math.random().toString(36).slice(2)}@openformvault.test`;
const password = `Ofv!${Date.now()}!popup`;
const item = {
  title: 'CDP Popup E2E Login',
  url: 'https://example-cdp.openformvault.test/login',
  username: 'popup-user@example.test',
  password: `PopupSecret-${Date.now()}`,
  otpSecret: 'JBSWY3DPEHPK3PXP',
  notes: 'Created by CDP popup E2E verifier.'
};

const profile = await mkdtemp(path.join(tmpdir(), 'ofv-cdp-profile-'));
const chromeArgs = [
  `--remote-debugging-port=${port}`,
  `--user-data-dir=${profile}`,
  '--no-first-run',
  '--no-default-browser-check',
  '--disable-background-networking',
  '--disable-component-update',
  '--disable-sync',
  '--disable-extensions-file-access-check',
  '--enable-unsafe-extension-debugging',
  '--no-sandbox',
  '--headless=new',
  'about:blank'
];
const proc = spawn(chrome, chromeArgs, { stdio: ['ignore', 'pipe', 'pipe'] });
let chromeOutput = '';
proc.stderr.on('data', d => { chromeOutput += d.toString(); });
proc.stdout.on('data', d => { chromeOutput += d.toString(); });

function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
async function waitForJson(url, attempts = 80) {
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url);
      if (response.ok) return await response.json();
    } catch {}
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${url}. Chrome output: ${chromeOutput.slice(-2000)}`);
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  ws.addEventListener('message', event => {
    const msg = JSON.parse(event.data);
    if (!msg.id || !pending.has(msg.id)) return;
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result ?? {});
  });
  return new Promise((resolve, reject) => {
    ws.addEventListener('open', () => resolve({
      send(method, params = {}, sessionId = undefined) {
        const callId = ++id;
        const message = { id: callId, method, params };
        if (sessionId) message.sessionId = sessionId;
        ws.send(JSON.stringify(message));
        return new Promise((resolve, reject) => pending.set(callId, { resolve, reject }));
      },
      close() { ws.close(); }
    }));
    ws.addEventListener('error', reject, { once: true });
  });
}

async function evalInPage(browser, sessionId, expression) {
  const result = await browser.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result?.value;
}

async function waitFor(browser, sessionId, expression, timeoutMs = 15000) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeoutMs) {
    last = await evalInPage(browser, sessionId, expression);
    if (last?.ok) return last;
    await sleep(250);
  }
  throw new Error(`Timed out waiting for ${expression}. Last=${JSON.stringify(last)}`);
}

function jsString(value) { return JSON.stringify(value); }

async function decryptSnapshot(snapshot, masterPassword) {
  const subtle = webcrypto.subtle;
  const enc = new TextEncoder();
  const material = await subtle.importKey('raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveKey']);
  const salt = Uint8Array.from(Buffer.from(snapshot.salt, 'base64'));
  const nonce = Uint8Array.from(Buffer.from(snapshot.nonce, 'base64'));
  const key = await subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 310000 }, material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  const plaintext = await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, Buffer.from(snapshot.ciphertext, 'base64'));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function serverReadback() {
  const login = await fetch(`${serverUrl}/v1/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  if (!login.ok) throw new Error(`server login failed HTTP ${login.status}: ${await login.text()}`);
  const { token } = await login.json();
  const snapResponse = await fetch(`${serverUrl}/v1/vault/snapshot`, { headers: { authorization: `Bearer ${token}` } });
  if (!snapResponse.ok) throw new Error(`snapshot readback failed HTTP ${snapResponse.status}: ${await snapResponse.text()}`);
  const snapshot = await snapResponse.json();
  const decrypted = await decryptSnapshot(snapshot, password);
  return { revision: snapshot.revision, decrypted };
}

let browser;
try {
  const version = await waitForJson(`http://127.0.0.1:${port}/json/version`);
  browser = await cdp(version.webSocketDebuggerUrl);
  const loadResult = await browser.send('Extensions.loadUnpacked', { path: extensionDir });
  const extensionId = loadResult.id || loadResult.extensionId;
  if (!extensionId) throw new Error(`Extensions.loadUnpacked returned no id: ${JSON.stringify(loadResult)}`);
  const popupUrl = `chrome-extension://${extensionId}/popup.html`;
  const { targetId } = await browser.send('Target.createTarget', { url: popupUrl });
  await sleep(1000);
  const { sessionId } = await browser.send('Target.attachToTarget', { targetId, flatten: true });
  await browser.send('Runtime.enable', {}, sessionId);
  const popup = await evalInPage(browser, sessionId, `(() => ({
    href: location.href,
    title: document.title,
    ready: document.readyState,
    body: document.body?.innerText || '',
    ids: [...document.querySelectorAll('[id]')].map(e => e.id),
    hasVaultSearch: !!document.querySelector('#vault-search'),
    hasSettingsPanel: !!document.querySelector('#settings-panel'),
    hasServerSettings: document.body.innerText.includes('Server')
  }))()`);
  const requiredIds = ['auth', 'username', 'password', 'login', 'register', 'vault', 'vault-search', 'settings-panel', 'items'];
  const missingIds = requiredIds.filter(id => !popup.ids.includes(id));
  if (missingIds.length) throw new Error(`Popup missing required controls: ${missingIds.join(', ')}`);

  let flow = null;
  if (runFlow) {
    await evalInPage(browser, sessionId, `(() => {
      document.querySelector('#server-url').value = ${jsString(serverUrl)};
      document.querySelector('#username').value = ${jsString(username)};
      document.querySelector('#password').value = ${jsString(password)};
      document.querySelector('#register').click();
      document.querySelector('#confirm-password').value = ${jsString(password)};
      document.querySelector('#register').click();
      return true;
    })()`);
    await waitFor(browser, sessionId, `(() => ({ ok: !document.querySelector('#vault').hidden, status: document.querySelector('#status').textContent, sync: document.querySelector('#sync-state').textContent }))()`, 20000);
    await evalInPage(browser, sessionId, `(() => {
      document.querySelector('#add-login').click();
      document.querySelector('#item-title').value = ${jsString(item.title)};
      document.querySelector('#item-url').value = ${jsString(item.url)};
      document.querySelector('#item-username').value = ${jsString(item.username)};
      document.querySelector('#item-password').value = ${jsString(item.password)};
      document.querySelector('#item-otp-secret').value = ${jsString(item.otpSecret)};
      document.querySelector('#item-notes').value = ${jsString(item.notes)};
      document.querySelector('#save-login').click();
      return true;
    })()`);
    const pushed = await waitFor(browser, sessionId, `(() => {
      const status = document.querySelector('#status').textContent;
      const sync = document.querySelector('#sync-state').textContent;
      const body = document.body.innerText;
      return { ok: /Pushed revision|synced/i.test(status + ' ' + sync), status, sync, body };
    })()`, 20000);
    const visible = await evalInPage(browser, sessionId, `(() => ({
      vaultHidden: document.querySelector('#vault').hidden,
      itemText: document.querySelector('#items').innerText,
      status: document.querySelector('#status').textContent,
      sync: document.querySelector('#sync-state').textContent
    }))()`);
    const readback = await serverReadback();
    const serverItem = readback.decrypted.items.find(x => x.title === item.title);
    if (!serverItem) throw new Error(`Server readback did not contain item. Decrypted=${JSON.stringify(readback.decrypted)}`);
    for (const key of ['url', 'username', 'password', 'otpSecret', 'notes']) {
      if (serverItem[key] !== item[key]) throw new Error(`Server readback ${key} mismatch: expected ${item[key]}, got ${serverItem[key]}`);
    }
    flow = { username, item, pushed, visible, serverReadback: { revision: readback.revision, item: serverItem } };
  }

  const targets = await waitForJson(`http://127.0.0.1:${port}/json/list`);
  const result = {
    chromeVersion: version.Browser,
    extensionId,
    popupUrl,
    popup,
    popupUiVerified: popup.hasVaultSearch && popup.hasSettingsPanel && popup.hasServerSettings,
    flowVerified: Boolean(flow),
    flow,
    extensionTargets: targets.filter(t => t.url?.startsWith('chrome-extension://')).map(t => ({ type: t.type, url: t.url, title: t.title }))
  };
  console.log(JSON.stringify(result, null, 2));
} finally {
  try { browser?.close(); } catch {}
  proc.kill('SIGTERM');
  await sleep(1000);
  try { await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {}
}

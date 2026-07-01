import assert from 'node:assert/strict';
import test from 'node:test';

const base = process.env.OFV_TEST_SERVER ?? 'https://openformvault.guber.dev';

async function json(path, options = {}) {
  const response = await fetch(`${base}${path}`, { ...options, headers: { 'content-type': 'application/json', ...(options.headers ?? {}) } });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(`${response.status} ${text}`);
  return body;
}

test('server supports account auth and encrypted vault snapshot conflict checks', async () => {
  const username = `it-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const password = 'CorrectHorseBattery123!';
  const registered = await json('/v1/users/register', { method: 'POST', body: JSON.stringify({ username, password }) });
  assert.equal(registered.username, username);
  assert.ok(registered.token);

  const loggedIn = await json('/v1/session', { method: 'POST', body: JSON.stringify({ username, password }) });
  assert.ok(loggedIn.token);

  const auth = { authorization: `Bearer ${loggedIn.token}` };
  const put1 = await json('/v1/vault/snapshot', { method: 'PUT', headers: auth, body: JSON.stringify({ ciphertext: 'cipher-a', nonce: 'nonce-a', salt: 'salt-a', algorithm: 'test', kdf: 'test', baseRevision: null }) });
  assert.equal(put1.revision, 1);

  const pulled = await json('/v1/vault/snapshot', { headers: auth });
  assert.equal(pulled.revision, 1);
  assert.equal(pulled.ciphertext, 'cipher-a');

  const stale = await fetch(`${base}/v1/vault/snapshot`, { method: 'PUT', headers: { ...auth, 'content-type': 'application/json' }, body: JSON.stringify({ ciphertext: 'cipher-b', nonce: 'nonce-b', salt: 'salt-b', algorithm: 'test', kdf: 'test', baseRevision: 0 }) });
  assert.equal(stale.status, 409);
});

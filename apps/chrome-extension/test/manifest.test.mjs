import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const manifest = JSON.parse(await readFile(new URL('../extension/manifest.json', import.meta.url), 'utf8'));
const popupSource = await readFile(new URL('../extension/popup.js', import.meta.url), 'utf8');
const popupHtml = await readFile(new URL('../extension/popup.html', import.meta.url), 'utf8');
const serverSource = await readFile(new URL('../../../apps/server/src/OpenFormVault.Server/Program.cs', import.meta.url), 'utf8');

test('extension uses Manifest V3 with explicit action and service worker', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.action.default_popup);
  assert.equal(manifest.background.type, 'module');
  assert.ok(manifest.background.service_worker);
});

test('extension starts with minimal permissions and only the production server host permission', () => {
  assert.deepEqual(manifest.host_permissions, ['https://openformvault.guber.dev/*']);
  assert.ok(manifest.permissions.includes('storage'));
  assert.ok(manifest.permissions.includes('activeTab'));
});

test('RoboForm import recognizes real export headers without losing encrypted fields', () => {
  assert.match(popupSource, /['"]pwd['"]/i);
  assert.match(popupSource, /['"]matchurl['"]/i);
  assert.match(popupSource, /rffieldsv2/i);
  assert.match(popupSource, /__extra/);
});

test('popup keeps end-user vault surface separate from settings and diagnostics', () => {
  assert.match(popupHtml, /id="auth"[^>]*class="[^"]*auth-screen/);
  assert.match(popupHtml, /id="vault-search"/);
  assert.match(popupHtml, /id="settings-panel"/);
  assert.match(popupHtml, /<label>Server <input id="server-url"/);
  assert.match(popupHtml, /<summary>Import from RoboForm or CSV<\/summary>/);
  assert.doesNotMatch(popupHtml, /Revision 0|Pull sync|Push sync|Test server|server status/i);
  assert.match(popupSource, /OpenFormVault.*is online|Connected to OpenFormVault|Server.*is online/s);
  assert.doesNotMatch(popupSource, /Server online:/);
});


test('auth screen shows server, registration confirmation, and eye password controls', () => {
  assert.match(popupHtml, /<label>Server <input id="server-url"/);
  assert.match(popupHtml, /id="confirm-password-row"/);
  assert.match(popupHtml, /id="confirm-password"/);
  assert.match(popupHtml, /id="show-master-password"[^>]*>👁<\/button>/);
  assert.match(popupHtml, /id="show-confirm-password"[^>]*>👁<\/button>/);
  assert.match(popupSource, /Passwords do not match/);
  assert.match(popupSource, /setAuthMode\('register'\)/);
});


test('popup exposes local security report and theme controls', () => {
  assert.match(popupHtml, /id="theme-mode"/);
  assert.match(popupHtml, /<option>System<\/option><option>Light<\/option><option>Dark<\/option>/);
  assert.match(popupHtml, /id="security-report"/);
  assert.match(popupSource, /function securityReport\(\)/);
  assert.match(popupSource, /Weak passwords|Missing OTP|HTTP-only sites/);
});

test('server accepts idempotent retry of a previously successful snapshot PUT', () => {
  assert.match(serverSource, /isRetryOfPreviousSuccess/);
  assert.match(serverSource, /idempotent = true/);
  assert.match(serverSource, /request\.BaseRevision\.Value \+ 1 == currentRevision/);
});

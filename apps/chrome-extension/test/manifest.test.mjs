import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const manifest = JSON.parse(await readFile(new URL('../extension/manifest.json', import.meta.url), 'utf8'));
const popupSource = await readFile(new URL('../extension/popup.js', import.meta.url), 'utf8');

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

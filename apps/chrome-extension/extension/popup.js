const status = document.getElementById('status');

document.getElementById('unlock').addEventListener('click', async () => {
  const serverUrl = document.getElementById('server-url').value.trim();
  const username = document.getElementById('username').value.trim();
  await chrome.storage.local.set({ serverUrl, username, syncStatus: 'unlock-scaffold' });
  status.textContent = 'Unlock scaffold saved locally. Vault crypto is implemented in the sync-core milestone.';
});

document.getElementById('sync-now').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ type: 'OFV_SYNC_NOW' });
  status.textContent = 'Sync request sent.';
});

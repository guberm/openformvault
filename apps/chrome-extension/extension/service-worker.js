chrome.runtime.onInstalled.addListener(async () => {
  await chrome.alarms.create('ofv-periodic-sync', { periodInMinutes: 5 });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === 'OFV_SYNC_NOW') {
      await chrome.storage.local.set({ syncStatus: 'sync-requested' });
      sendResponse({ ok: true });
      return;
    }
    sendResponse({ ok: false, error: 'unknown_message' });
  })();
  return true;
});

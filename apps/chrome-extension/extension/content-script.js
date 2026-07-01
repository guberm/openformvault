(() => {
  function findInputs() { return [...document.querySelectorAll('input')]; }
  function loginFields() {
    const inputs = findInputs();
    const passwordInput = inputs.find(input => (input.type || '').toLowerCase() === 'password');
    const usernameInput = inputs.find(input => ['text', 'email'].includes((input.type || 'text').toLowerCase()) || /user|email|login/i.test(input.name || input.id || input.autocomplete || ''));
    return { inputs, usernameInput, passwordInput };
  }

  const { passwordInput } = loginFields();
  if (passwordInput) document.documentElement.dataset.openformvaultLoginCandidate = 'true';

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type !== 'OFV_FILL_LOGIN') return false;
    const { usernameInput, passwordInput } = loginFields();
    if (usernameInput) {
      usernameInput.focus();
      usernameInput.value = message.username ?? '';
      usernameInput.dispatchEvent(new Event('input', { bubbles: true }));
      usernameInput.dispatchEvent(new Event('change', { bubbles: true }));
    }
    if (passwordInput) {
      passwordInput.focus();
      passwordInput.value = message.password ?? '';
      passwordInput.dispatchEvent(new Event('input', { bubbles: true }));
      passwordInput.dispatchEvent(new Event('change', { bubbles: true }));
    }
    sendResponse({ ok: Boolean(usernameInput || passwordInput) });
    return true;
  });

  document.addEventListener('submit', () => {
    const { usernameInput, passwordInput } = loginFields();
    if (!passwordInput?.value) return;
    chrome.runtime.sendMessage({
      type: 'OFV_SAVE_CANDIDATE',
      candidate: {
        title: document.title || location.hostname,
        url: location.origin,
        username: usernameInput?.value || '',
        password: passwordInput.value,
        detectedAt: new Date().toISOString()
      }
    }).catch(() => {});
  }, true);
})();

(() => {
  const inputs = [...document.querySelectorAll('input')];
  const hasPassword = inputs.some(input => input.type === 'password');
  if (hasPassword) {
    document.documentElement.dataset.openformvaultLoginCandidate = 'true';
  }
})();

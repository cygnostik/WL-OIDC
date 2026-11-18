const accountLink = document.getElementById('open-account-link');
const code = window.location.hash.slice(1);

if (accountLink && /^[a-f0-9]{64}$/.test(code)) {
    history.replaceState(null, '', window.location.pathname);
    accountLink.elements.namedItem('code').value = code;
    accountLink.requestSubmit();
}

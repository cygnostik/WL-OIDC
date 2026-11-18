import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

const issuer = process.env.PD_OIDC_ISSUER || 'http://127.0.0.1:3000';
const email = process.env.PD_TEST_EMAIL;
const password = process.env.PD_TEST_PASSWORD;
const changePolicy = process.env.PD_TEST_POLICY_CHANGES === '1';
const clientId = process.env.PD_TEST_CLIENT_ID || 'example-client';
const callback = process.env.PD_TEST_CALLBACK || 'https://app.example.test/auth/callback';
const expectedRole = process.env.PD_TEST_EXPECTED_ROLE || 'admin';
const registeredCallback = new URL(callback);
assert(email && password, 'Set PD_TEST_EMAIL and PD_TEST_PASSWORD for a fixture operator.');
if (changePolicy) {
    assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(issuer).hostname));
}

const metadata = await (await fetch(issuer + '/.well-known/openid-configuration')).json();
assert.equal(metadata.issuer, issuer);
assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ['none']);
const { keys } = await (await fetch(metadata.jwks_uri)).json();
assert(keys.length > 0);

function browser() {
    let cookie = '';
    return async (url, init = {}) => {
        const response = await fetch(url, {
            ...init,
            redirect: 'manual',
            headers: { ...init.headers, ...(cookie ? { cookie } : {}) },
        });
        const issuedCookie = response.headers.get('set-cookie');
        if (issuedCookie) {
            if (issuer.startsWith('https://')) {
                assert(issuedCookie.startsWith('__Host-pd_session='));
                assert.match(issuedCookie, /; secure/i);
            }
            assert.match(issuedCookie, /; httponly/i);
            cookie = issuedCookie.split(';', 1)[0];
        }
        return response;
    };
}

function authorization(overrides = {}) {
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(24).toString('base64url');
    const nonce = randomBytes(24).toString('base64url');
    const query = new URLSearchParams({
        client_id: clientId, redirect_uri: callback, response_type: 'code',
        scope: 'openid profile email', state, nonce, code_challenge_method: 'S256',
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        ...overrides,
    });
    return { verifier, state, nonce, url: metadata.authorization_endpoint + '?' + query };
}

function callbackParameters(response, state) {
    assert([302, 303].includes(response.status), 'Expected an authorization redirect, got ' + response.status);
    const location = new URL(response.headers.get('location'));
    assert.equal(location.origin + location.pathname, registeredCallback.origin + registeredCallback.pathname);
    for (const [key, value] of registeredCallback.searchParams) assert.equal(location.searchParams.get(key), value);
    assert.equal(location.searchParams.get('state'), state);
    return location.searchParams;
}

function tokenRequest(code, verifier, id = clientId, redirect = callback) {
    return fetch(metadata.token_endpoint, {
        method: 'POST',
        body: new URLSearchParams({
            grant_type: 'authorization_code', client_id: id,
            redirect_uri: redirect, code, code_verifier: verifier,
        }),
    });
}

const invalidCallback = await fetch(authorization({ redirect_uri: callback + '/different' }).url, { redirect: 'manual' });
assert.equal(invalidCallback.status, 400);
assert.equal(invalidCallback.headers.get('location'), null);
const plainPkce = await fetch(authorization({ code_challenge_method: 'plain' }).url, { redirect: 'manual' });
if (plainPkce.status === 400) {
    assert.equal(plainPkce.headers.get('location'), null);
} else {
    const redirect = new URL(plainPkce.headers.get('location'));
    assert.equal(redirect.origin + redirect.pathname, registeredCallback.origin + registeredCallback.pathname);
    assert(redirect.searchParams.has('error'));
    assert.equal(redirect.searchParams.has('code'), false);
}

const visit = browser();
const unsolicited = authorization({ prompt: 'none' });
assert.equal(callbackParameters(await visit(unsolicited.url), unsolicited.state).get('error'), 'login_required');
const login = authorization();
const form = await visit(login.url);
assert.equal(form.status, 200);
const html = await form.text();
const csrf = html.match(/name="csrf" value="([a-f0-9]+)"/)?.[1];
const flow = html.match(/name="flow" value="([a-f0-9]+)"/)?.[1];
assert(csrf && flow, 'Expected the sign-in form with CSRF and flow values.');
const wrongCsrf = await visit(issuer + '/login', {
    method: 'POST', body: new URLSearchParams({ csrf: 'invalid', flow, email, password }),
});
assert.equal(wrongCsrf.status, 400);
const signedIn = await visit(issuer + '/login', {
    method: 'POST', body: new URLSearchParams({ csrf, flow, email, password }),
});
const code = callbackParameters(signedIn, login.state).get('code');
assert(code);
if (process.env.PD_TEST_OTHER_CLIENT_ID && process.env.PD_TEST_OTHER_CALLBACK) {
    const crossClient = await tokenRequest(code, login.verifier, process.env.PD_TEST_OTHER_CLIENT_ID, process.env.PD_TEST_OTHER_CALLBACK);
    assert.equal(crossClient.status, 400, 'An authorization code must stay bound to its original client.');
}
const wrong = await tokenRequest(code, randomBytes(32).toString('base64url'));
assert.equal(wrong.status, 400);
const responses = await Promise.all([tokenRequest(code, login.verifier), tokenRequest(code, login.verifier)]);
assert.deepEqual(responses.map(response => response.status).sort(), [200, 400]);
const tokens = await responses.find(response => response.ok).json();
assert.equal(tokens.token_type, 'Bearer');
assert.equal(tokens.refresh_token, undefined);
const [header, payload, signature] = tokens.id_token.split('.');
const tokenHeader = JSON.parse(Buffer.from(header, 'base64url'));
const claims = JSON.parse(Buffer.from(payload, 'base64url'));
const jwk = keys.find(key => key.kid === tokenHeader.kid);
assert(jwk);
assert.equal(tokenHeader.alg, 'RS256');
assert(verify('RSA-SHA256', Buffer.from(header + '.' + payload), createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(signature, 'base64url')));
assert.equal(claims.iss, issuer);
assert.deepEqual([claims.aud].flat(), [clientId]);
assert.match(claims.sub, /^[a-f0-9]{32}$/);
assert.equal(claims.nonce, login.nonce);
assert.equal(claims.pd_role, expectedRole);
assert.equal(claims.email, email.toLowerCase());
assert.equal(claims.email_verified, true);
assert(claims.exp > Math.floor(Date.now() / 1000) && claims.exp - claims.iat <= 900);
assert.equal(claims.at_hash, createHash('sha256').update(tokens.access_token).digest().subarray(0, 16).toString('base64url'));

if (metadata.userinfo_endpoint) {
    const userinfo = await fetch(metadata.userinfo_endpoint, { headers: { authorization: 'Bearer ' + tokens.access_token } });
    assert.equal(userinfo.status, 200);
    assert.equal((await userinfo.json()).sub, claims.sub);
}

if (changePolicy) {
    const set = (...args) => execFileSync('php', ['bin/pd-oidc', ...args], { stdio: 'ignore' });
    const pending = authorization();
    const pendingCode = callbackParameters(await visit(pending.url), pending.state).get('code');
    assert(pendingCode, 'Expected the existing SSO session to issue a code.');
    try {
        set('set-service-access', email, clientId, 'deny');
        const denied = authorization();
        assert.equal(callbackParameters(await visit(denied.url), denied.state).get('error'), 'access_denied');
        assert.equal((await tokenRequest(pendingCode, pending.verifier)).status, 400);
    } finally {
        set('set-service-access', email, clientId, 'inherit');
    }

    try {
        set('set-service-role', email, clientId, 'read');
        const read = authorization();
        assert.equal(callbackParameters(await visit(read.url), read.state).get('error'), 'access_denied');
    } finally {
        set('set-service-role', email, clientId, 'inherit');
    }

    const beforeDisable = authorization();
    const beforeDisableCode = callbackParameters(await visit(beforeDisable.url), beforeDisable.state).get('code');
    assert(beforeDisableCode);
    set('set-enabled', email, 'off');
    set('set-enabled', email, 'on');
    const stale = authorization({ prompt: 'none' });
    assert.equal(callbackParameters(await visit(stale.url), stale.state).get('error'), 'login_required');
    assert.equal((await tokenRequest(beforeDisableCode, beforeDisable.verifier)).status, 400);
    if (metadata.userinfo_endpoint) {
        const staleUserInfo = await fetch(metadata.userinfo_endpoint, {
            headers: { authorization: 'Bearer ' + tokens.access_token },
        });
        assert.equal(staleUserInfo.status, 401);
    }
}

console.log('OIDC client passed discovery, callback, PKCE, single-use exchange and signed ID token checks.');
if (changePolicy) console.log('Existing SSO and issued codes respected live deny and account disablement.');

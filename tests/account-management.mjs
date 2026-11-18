import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { promisify } from 'node:util';

const issuer = process.env.PD_OIDC_ISSUER || 'http://127.0.0.1:3000';
const adminEmail = process.env.PD_TEST_ADMIN_EMAIL;
const adminPassword = process.env.PD_TEST_ADMIN_PASSWORD;
const applicant = process.env.PD_TEST_APPLICANT;
const readCode = process.env.PD_TEST_READ_CODE;
const client = process.env.PD_TEST_CLIENT_ID || 'example-client';
const callback = process.env.PD_TEST_CALLBACK || 'https://app.example.test/auth/callback';
const serviceName = process.env.PD_TEST_SERVICE_NAME || 'Example service';
const run = promisify(execFile);
assert(adminEmail && adminPassword && applicant && readCode, 'Use a disposable admin, applicant and fixture code reader.');

function browser() {
    let cookie = '';
    return async (path, fields) => {
        const response = await fetch(issuer + path, {
            redirect: 'manual',
            headers: { connection: 'close', ...(cookie ? { cookie } : {}) },
            ...(fields ? { method: 'POST', body: new URLSearchParams(fields) } : {}),
        });
        const updated = response.headers.get('set-cookie');
        if (updated) cookie = updated.split(';', 1)[0];
        return {
            status: response.status,
            location: response.headers.get('location'),
            policy: response.headers.get('content-security-policy'),
            html: await response.text(),
        };
    };
}

function field(html, name) {
    const value = html.match(new RegExp('name="' + name + '" value="([a-f0-9]+)"'))?.[1];
    assert(value, 'Expected form field ' + name);
    return value;
}

async function post(visit, path, fields) {
    const form = await visit(path);
    assert.equal(form.status, 200, path);
    return visit(path, { csrf: field(form.html, 'csrf'), ...fields });
}

async function signIn(visit, email, password) {
    const page = await visit('/');
    return visit('/login', { csrf: field(page.html, 'csrf'), flow: '', email, password });
}

async function openLink(visit, code) {
    return post(visit, '/password/reset', { action: 'open', code });
}

async function token(purpose) {
    const { stdout } = await run(readCode, [purpose, applicant], { encoding: 'utf8', timeout: 90_000 });
    const code = stdout.trim();
    assert(/^[a-f0-9]{64}$/.test(code), 'Expected a code for ' + purpose);
    return code;
}

const visitor = browser();
const landing = await visitor('/');
assert.match(landing.html, /<\/form>\s*<nav[^>]*>\s*<a href="\/create-account">Create account<\/a>[\s\S]*Forgot password\?/);
assert.equal((await visitor('/admin')).status, 303);
const signup = await visitor('/create-account');
assert.match(signup.html, /Which system should the admin assign you to\?/);
assert(!signup.html.includes(client) && !signup.html.includes(serviceName));
assert(!signup.policy.includes(new URL(callback).hostname));
const originalPassword = randomBytes(28).toString('base64url');
assert.equal((await signIn(browser(), applicant, originalPassword)).status, 401);
assert.equal((await visitor('/create-account', {
    csrf: field(signup.html, 'csrf'), first_name: 'Access', last_name: 'Smoke',
    email: applicant, note: 'Please assign me to <pilot>.',
})).status, 303);
assert.match((await visitor('/create-account')).html, /submitted for review/);

const admin = browser();
assert.equal((await signIn(admin, adminEmail, adminPassword)).location, '/account');
const manager = await admin('/admin');
assert.equal(manager.status, 200);
const request = [...manager.html.matchAll(/<article[^>]*>[\s\S]*?<\/article>/g)].find(([row]) => row.includes(applicant))?.[0];
assert(request?.includes('&lt;pilot&gt;'));
const decision = { id: field(request, 'id'), service: client, assigned_role: 'admin', decision: 'approve' };
assert.equal((await admin('/admin', { ...decision, csrf: 'wrong' })).status, 400);
assert.equal((await admin('/admin', { ...decision, csrf: field(request, 'csrf') })).location, '/admin');
assert.match((await admin('/admin')).html, /setup email is queued/);
assert.equal((await signIn(browser(), applicant, originalPassword)).status, 401);

const activation = await token('activate');
const setup = browser();
assert.equal((await openLink(setup, activation)).location, '/password/reset');
assert.match((await setup('/password/reset')).html, /Set your password/);
assert.equal((await post(setup, '/password/reset', { action: 'save', password: originalPassword, confirm: originalPassword })).location, '/');

const member = browser();
assert.equal((await signIn(member, applicant, originalPassword)).location, '/account');
assert.equal((await member('/admin')).status, 403);
assert.equal((await member('/admin', decision)).status, 403);
assert.equal((await member('/admin/user?subject=00000000000000000000000000000000')).status, 403);
const reusedActivation = browser();
await openLink(reusedActivation, activation);
assert.match((await reusedActivation('/password/reset')).html, /already used/);

const emailForm = browser();
assert.equal((await post(emailForm, '/password/forgot', { email: applicant })).location, '/password/forgot');
const known = (await emailForm('/password/forgot')).html.match(/If an eligible account[^<]+/)?.[0];
assert(known);
assert.equal((await post(emailForm, '/password/forgot', { email: 'unknown-' + randomBytes(10).toString('hex') + '@example.invalid' })).location, '/password/forgot');
assert((await emailForm('/password/forgot')).html.includes(known));

const recovery = await token('reset');
const first = browser();
const second = browser();
assert.equal((await openLink(first, recovery)).location, '/password/reset');
assert.equal((await openLink(second, recovery)).location, '/password/reset');
const newPassword = randomBytes(28).toString('base64url');
const forms = await Promise.all([first('/password/reset'), second('/password/reset')]);
const saves = await Promise.all([first, second].map((visit, i) => visit('/password/reset', {
    csrf: field(forms[i].html, 'csrf'), action: 'save', password: newPassword, confirm: newPassword,
})));
assert.equal(saves.filter(result => result.location === '/').length, 1);
assert.match((await member('/account')).html, /Sign in to/);
assert.equal((await signIn(browser(), applicant, originalPassword)).status, 401);
assert.equal((await signIn(browser(), applicant, newPassword)).location, '/account');
const reused = browser();
await openLink(reused, recovery);
assert.match((await reused('/password/reset')).html, /already used/);

const users = await admin('/admin?' + new URLSearchParams({ q: applicant }));
const subject = users.html.match(/\/admin\/user\?subject=([a-f0-9]{32})/)?.[1];
assert(subject);
assert.equal((await post(admin, '/admin/user?subject=' + subject, {
    status: 'disabled', access_mode: 'selected', default_role: 'read',
    ['access[' + client + ']']: 'deny',
    ['service_role[' + client + ']']: 'inherit',
})).location, '/admin/user?subject=' + subject);
const disabled = await admin('/admin/user?subject=' + subject);
assert.match(disabled.html, /value="disabled" selected/);
assert.match(disabled.html, /value="deny" selected/);
assert.equal((await signIn(browser(), applicant, newPassword)).status, 401);
console.log('Signup, identity admin approval, mailbox setup and recovery, concurrent single use, session invalidation and user policy passed.');

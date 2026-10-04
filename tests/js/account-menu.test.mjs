import { strict as assert } from 'node:assert';
import { existsSync, readFileSync } from 'node:fs';
import { describe, it } from 'node:test';

const path = new URL('../../app/static/account-menu.js', import.meta.url);
const source = existsSync(path) ? readFileSync(path, 'utf8') : '';

function account(fetchResponse = async () => ({ ok: true, json: async () => ({ email: 'new@example.com' }) })) {
  const calls = [];
  const focused = [];
  const window = { location: { href: '' } };
  class FormData {
    constructor(form) { this.values = { ...form.values }; }
    get(name) { return this.values[name] || ''; }
  }
  new Function('window', 'fetch', 'FormData', source)(window, async (...args) => {
    calls.push(args);
    return fetchResponse(...args);
  }, FormData);
  assert.equal(typeof window.accountMenu, 'function', 'the account menu controller is missing');
  const c = window.accountMenu();
  const focusable = (name) => ({ focus: () => focused.push(name) });
  const form = {
    values: {},
    reset() { this.values = {}; },
    elements: { namedItem: (name) => ({
      ...focusable(name),
      get value() { return form.values[name] || ''; },
      set value(value) { form.values[name] = value; },
    }) },
  };
  c.$el = { dataset: { email: 'user@example.com' } };
  c.$refs = {
    form, trigger: focusable('trigger'), error: focusable('error'), done: focusable('done'),
    dialog: { open: false, showModal() { this.open = true; }, close() { this.open = false; } },
  };
  c.$nextTick = (fn) => Promise.resolve().then(fn);
  c.init();
  return { c, form, calls, focused, window };
}

describe('account changes from the navigation', () => {
  it('opens in place, focuses the first field, and clears secrets when cancelled', async () => {
    const { c, form, focused } = account();
    c.open = true;
    await c.edit('password');
    assert.equal(c.open, false);
    assert.equal(c.$refs.dialog.open, true);
    assert.equal(focused.at(-1), 'current_password');
    assert.equal(form.values.username, 'user@example.com', 'form reset must preserve the password-manager identity');
    form.values = { current_password: 'old secret', password: 'new secret' };
    c.closeDialog();
    assert.equal(c.$refs.dialog.open, false);
    c.dialogClosed();
    assert.deepEqual(form.values, {});
    assert.equal(focused.at(-1), 'trigger');
    await c.edit('email');
    assert.equal(focused.at(-1), 'email');
  });

  it('sends only the email and current password, updates the nav, and stays signed in', async () => {
    const { c, form, calls, window } = account();
    await c.edit('email');
    form.values = { email: '  new@example.com  ', current_password: 'current secret', password: 'stale', username: c.email };
    await c.save();
    assert.equal(calls[0][0], '/api/users/me');
    assert.equal(calls[0][1].method, 'PATCH');
    assert.equal(calls[0][1].credentials, 'same-origin');
    assert.equal(calls[0][1].headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(calls[0][1].body), { email: 'new@example.com', current_password: 'current secret' });
    assert.equal(c.email, 'new@example.com');
    assert.equal(c.success, true);
    assert.equal(c.needsLogin, false);
    assert.deepEqual(form.values, {});
    c.closeDialog();
    assert.equal(window.location.href, '');
    c.dialogClosed();
    await c.edit('password');
    assert.equal(form.values.username, 'new@example.com', 'future password changes use the updated identity');
  });

  it('rejects a mismatched confirmation before sending any request', async () => {
    const { c, form, calls, focused } = account();
    await c.edit('password');
    form.values = { current_password: 'current secret', password: 'new secret', confirm_password: 'different' };
    await c.save();
    assert.equal(calls.length, 0);
    assert.match(c.error, /match/i);
    assert.equal(focused.at(-1), 'confirm_password');
  });

  it('sends passwords unchanged and requires a new login after success', async () => {
    const { c, form, calls, window } = account();
    await c.edit('password');
    form.values = { current_password: ' old secret ', password: ' new secret ', confirm_password: ' new secret ' };
    await c.save();
    assert.deepEqual(JSON.parse(calls[0][1].body), { password: ' new secret ', current_password: ' old secret ' });
    assert.equal(c.success, true);
    assert.equal(c.needsLogin, true);
    assert.deepEqual(form.values, {});
    assert.equal(window.location.href, '', 'show the confirmation before navigating');
    c.closeDialog();
    assert.equal(window.location.href, '/auth/login');
  });

  it('does not submit an unchanged email', async () => {
    const { c, form, calls } = account();
    await c.edit('email');
    form.values = { email: c.email, current_password: 'secret' };
    await c.save();
    assert.equal(calls.length, 0);
    assert.match(c.error, /different email/i);
  });

  it('prevents duplicate submissions and closing while a change is pending', async () => {
    let resolve;
    const { c, form, calls } = account(() => new Promise((r) => { resolve = r; }));
    await c.edit('email');
    form.values = { email: 'new@example.com', current_password: 'secret' };
    const saving = c.save();
    assert.equal(c.busy, true);
    await c.save();
    c.closeDialog();
    assert.equal(c.$refs.dialog.open, true);
    assert.equal(calls.length, 1);
    resolve({ ok: true, json: async () => ({ email: 'new@example.com' }) });
    await saving;
    assert.equal(c.busy, false);
  });

  for (const [status, detail, message] of [
    [400, 'UPDATE_USER_EMAIL_ALREADY_EXISTS', /email.*already/i],
    [400, { code: 'UPDATE_USER_INVALID_PASSWORD', reason: 'The current password is required to change the password or email.' }, /current password.*incorrect/i],
    [400, { code: 'UPDATE_USER_INVALID_PASSWORD', reason: 'Password is a known default/common value — choose a stronger one.' }, /stronger/i],
    [422, [{ loc: ['body', 'email'], input: 'DO NOT ECHO', msg: 'bad email' }], /valid email/i],
    [429, null, /too many/i],
    [403, null, /reload/i],
    [500, null, /try again/i],
  ]) {
    it(`explains a ${status} rejection without reporting success or exposing validation input`, async () => {
      const { c, form } = account(async () => ({ ok: false, status, json: async () => ({ detail }) }));
      await c.edit('email');
      form.values = { email: 'new@example.com', current_password: 'secret' };
      await c.save();
      assert.match(c.error, message);
      assert.doesNotMatch(c.error, /DO NOT ECHO/);
      assert.equal(c.success, false);
      assert.equal(c.email, 'user@example.com');
      assert.equal(c.busy, false);
    });
  }

  it('offers sign-in when the session has expired and clears the form', async () => {
    const { c, form } = account(async () => ({ ok: false, status: 401, json: async () => ({ detail: 'Unauthorized' }) }));
    await c.edit('email');
    form.values = { email: 'new@example.com', current_password: 'secret' };
    await c.save();
    assert.equal(c.needsLogin, true);
    assert.match(c.error, /session.*expired/i);
    assert.deepEqual(form.values, {});
  });

  for (const failure of ['network', 'non-json']) {
    it(`handles a ${failure} failure and allows retry`, async () => {
      const { c, form } = account(async () => {
        if (failure === 'network') throw new TypeError('Failed to fetch');
        return { ok: false, status: 502, json: async () => { throw new SyntaxError('Bad JSON'); } };
      });
      await c.edit('email');
      form.values = { email: 'new@example.com', current_password: 'secret' };
      await c.save();
      assert.ok(c.error);
      assert.equal(c.busy, false);
      assert.equal(c.success, false);
      assert.equal(c.email, 'user@example.com');
    });
  }
});

/*
 * The page's send path, under node: `node tests/page.js` (no dependencies, no runner).
 *
 * pytest never loads index.html, so the rule that decides how a request leaves the
 * browser -- posted to this server, which attaches the credentials, or sent straight
 * from the page with none -- has no Python test. This runs the real script from the
 * HTML against a DOM shim just big enough to dispatch a submit and see what `fetch`
 * was handed.
 *
 * What it is really for: nothing the page can be made to do should get a credential
 * out of this server for a host that is not the backend. The tokens are no longer in
 * the browser at all, so what is checked here is that a lookalike URL cannot get its
 * request forwarded -- and, on the server side, tests/test_proxy.py checks the same
 * URLs again, because that is where the boundary actually is.
 *
 * It is a shim, not a browser: it knows only the handful of DOM features the page uses,
 * so a change to the page may need a change here. Prints a line per check and exits
 * non-zero on the first failure.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const html = fs.readFileSync(path.join(__dirname, '../src/entra_server/static/index.html'), 'utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];

// ---------------------------------------------------------------------------
// The shim
// ---------------------------------------------------------------------------

class El {
  constructor(tag = 'div') {
    this.tag = tag;
    this.children = [];
    this.value = '';
    this.checked = false;
    this.textContent = '';
    this.disabled = false;
    this.listeners = {};
    this.style = {};
    this.classes = new Set();
    this.classList = {
      add: (name) => this.classes.add(name),
      remove: (name) => this.classes.delete(name),
      toggle: (name, on) => (on ? this.classes.add(name) : this.classes.delete(name)),
    };
  }
  get hidden() { return this.classes.has('hide'); }
  // addRow() builds its inputs and button this way; nothing else needs parsing.
  set innerHTML(markup) {
    this.children = (markup.match(/<(input|button)\b/g) || []).map((tag) => new El(tag.slice(1)));
    this._html = markup;
  }
  get innerHTML() { return this._html || ''; }
  querySelectorAll(selector) { return this.children.filter((child) => child.tag === selector); }
  querySelector(selector) { return this.querySelectorAll(selector)[0]; }
  appendChild(child) { this.children.push(child); child.parent = this; return child; }
  replaceChildren() { this.children = []; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this);
  }
  focus() {}
  addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
  dispatch(name) {
    return Promise.all((this.listeners[name] || []).map((fn) => fn({ preventDefault() {} })));
  }
}

const ids = {};
for (const id of ['method', 'url', 'body', 'replace-page', 'send', 'form', 'headers', 'params',
                  'auth-note', 'url-preview', 'body-note', 'add-header', 'add-param', 'extract-params',
                  'result', 'result-meta', 'result-headers', 'result-headers-wrap', 'result-body',
                  'added-headers', 'added-header-rows']) {
  ids[id] = new El('div');
}
ids.method.value = 'GET';  // the first <option>, as a browser would have it

// document.open() discards the current document. Everything the page held on to is then
// detached, and getElementById finds only what was written in its place -- which is what
// makes a handler that runs afterwards reach for a form that is not there.
let replaced = false;
const backButton = new El('button');

global.document = {
  getElementById: (id) => (replaced ? (id === '__back' ? backButton : null) : ids[id]),
  createElement: (tag) => new El(tag),
  baseURI: 'https://app.example.com/',
  cookie: '',
  open() { replaced = true; }, write() {}, close() {},
};
global.location = { protocol: 'https:', reload() {} };
global.performance = { now: () => Date.now() };

const BACKEND = 'https://backend.example.com/api/';
const json = (body) => ({
  ok: true, status: 200, statusText: 'OK',
  headers: new Map([['content-type', 'application/json']]),
  json: async () => body,
});

// What the page asked for, whichever way it went: `sent.url` is where the browser
// pointed fetch, and `sent.forwarded` is the payload if it went through the server.
let sent = null;
global.fetch = async (url, init) => {
  if (url === '/api/backend') return json({ enabled: true, url: BACKEND });

  sent = { url, init, forwarded: null };
  if (url === '/api/send') {
    sent.forwarded = JSON.parse(init.body);
    return json({
      status: 200, reason: 'OK', url: sent.forwarded.url,
      headers: [['content-type', 'text/plain'], ['x-from', 'the backend']],
      body: 'hello', added: ['Authorization', 'token'], truncated: false,
    });
  }
  return {
    ok: true, status: 200, statusText: 'OK', url,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'hello',
  };
};

new Function(script)();

/** Fill in the URL and any header rows, and let the page react as it would to typing. */
async function fillIn(url, headerRows = []) {
  ids.url.value = url;
  ids.headers.replaceChildren();
  for (const [name, value] of headerRows) {
    const row = new El('div');
    row.innerHTML = '<input><input><button>';
    const [nameInput, valueInput] = row.querySelectorAll('input');
    nameInput.value = name;
    valueInput.value = value;
    ids.headers.appendChild(row);
  }
  await ids.url.dispatch('input');
  await ids.headers.dispatch('input');
  await settle();
}

/** Submit the form, and return what fetch was handed. */
async function send(url, headerRows = []) {
  sent = null;
  await fillIn(url, headerRows);
  await ids.form.dispatch('submit');
  return sent;
}

/** The name/value pairs shown in the "added by this server" rows. */
const addedRows = () =>
  ids['added-header-rows'].children.map((row) => row.querySelectorAll('input').map((i) => i.value));

// The rows are drawn from an async handler that fetches, so let its promises run first.
const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

(async () => {
  const backend = await send(BACKEND + 'things');
  assert.strictEqual(backend.url, '/api/send');
  assert.deepStrictEqual(backend.forwarded, {
    method: 'GET', url: BACKEND + 'things', headers: {}, body: null,
  });
  console.log('ok  a request to the backend is handed to this server to make');

  // Nothing of the browser's own goes with it: the credentials are attached there.
  const carried = JSON.stringify(backend.init.headers) + JSON.stringify(backend.forwarded.headers);
  assert.ok(!/authorization|bearer|token/i.test(carried), `the browser sent a credential: ${carried}`);
  console.log('ok  the browser holds no credential to send');

  const elsewhere = [
    'https://evil.example.com/api/things',        // another origin
    'https://backend.example.com/apiXX/things',   // a lookalike path
    'http://backend.example.com/api/things',      // another scheme
    'https://app.example.com/',                   // this server
  ];
  for (const url of elsewhere) {
    const away = await send(url);
    assert.notStrictEqual(away.url, '/api/send', `${url} was forwarded with credentials`);
    assert.strictEqual(away.url, url);
    assert.deepStrictEqual(away.init.headers, {}, `${url} was sent something of ours`);
  }
  console.log('ok  every other origin, path or scheme is sent straight from the browser');

  // A header typed into the form is forwarded as typed; the server leaves it alone.
  const typed = await send(BACKEND + 'things', [['Token', 'mine-not-yours']]);
  assert.deepStrictEqual(typed.forwarded.headers, { Token: 'mine-not-yours' });
  console.log('ok  a header typed into the form is forwarded as it was typed');

  // What the page shows about the headers it is not sending itself.
  await fillIn(BACKEND + 'things');
  const shown = addedRows();
  assert.deepStrictEqual(shown, [
    ['Authorization', 'added by this server'],
    ['token', 'added by this server'],
  ]);
  assert.ok(!ids['added-headers'].hidden, 'the added rows should be visible');
  console.log('ok  both added headers are listed, with no value to show');

  await fillIn('https://evil.example.com/api/things');
  assert.deepStrictEqual(addedRows(), [], 'nothing is added for another host');
  assert.ok(ids['added-headers'].hidden, 'so the block should be hidden');
  console.log('ok  nothing is listed for a URL outside the backend');

  await fillIn(BACKEND + 'things', [['token', 'mine-not-yours']]);
  assert.deepStrictEqual(addedRows().map(([name]) => name), ['Authorization']);
  console.log('ok  a header typed into the form drops out of the list');

  // The response panel reports what the server said it did, not what the page assumed.
  await send(BACKEND + 'things');
  await settle();
  const meta = ids['result-meta'].innerHTML;
  for (const expected of ['sent by this server', 'Authorization added', 'token added']) {
    assert.ok(meta.includes(expected), `the response panel should say "${expected}": ${meta}`);
  }
  assert.ok(ids['result-headers'].textContent.includes('x-from: the backend'), 'headers shown');
  console.log('ok  the response panel reports what the server attached');

  // Last, because replacing the document is one way: the shim has no elements afterwards.
  // A rejection here is the failure -- it is what "Cannot read properties of null" was.
  ids['replace-page'].checked = true;
  await send(BACKEND + 'things');
  await settle();
  assert.ok(replaced, 'the response should have replaced the document');
  console.log('ok  replacing the page leaves nothing reaching for the removed form');
})();

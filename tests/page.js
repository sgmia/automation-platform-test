/*
 * The page's send path, under node: `node tests/page.js` (no dependencies, no runner).
 *
 * pytest never loads index.html, so the rule that decides which credentials leave the
 * browser -- the backend access token in `Authorization`, and the visitor's id_token in
 * `token` -- has no Python test. This runs the real script from the HTML against a DOM
 * shim just big enough to dispatch a submit and see what `fetch` was handed.
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
const ID_TOKEN = 'the.id.token';
const json = (body) => ({
  ok: true, status: 200, statusText: 'OK',
  headers: new Map([['content-type', 'application/json']]),
  json: async () => body,
});

let sent = null;
global.fetch = async (url, init) => {
  if (url === '/oauth2/backend-token') {
    return json({ access_token: 'backend-access-token', expires_in: 3600, backend_url: BACKEND });
  }
  if (url === '/oauth2/id-token') return json({ id_token: ID_TOKEN, expires_in: 1800 });
  sent = { url, init };
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

/** Submit the form and return the headers fetch was handed. */
async function send(url, headerRows = []) {
  sent = null;
  await fillIn(url, headerRows);
  await ids.form.dispatch('submit');
  return sent.init.headers;
}

/** The name/value pairs shown in the "added automatically" rows. */
const addedRows = () =>
  ids['added-header-rows'].children.map((row) => row.querySelectorAll('input').map((i) => i.value));

// The rows are drawn from an async handler that fetches, so let its promises run first.
const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

(async () => {
  const backend = await send(BACKEND + 'things');
  assert.strictEqual(backend.token, ID_TOKEN);
  assert.strictEqual(backend.Authorization, 'Bearer backend-access-token');
  console.log('ok  a request to the backend carries both tokens');

  const elsewhere = [
    'https://evil.example.com/api/things',        // another origin
    'https://backend.example.com/apiXX/things',   // a lookalike path
    'http://backend.example.com/api/things',      // another scheme
    'https://app.example.com/',                   // this server
  ];
  for (const url of elsewhere) {
    const headers = await send(url);
    assert.strictEqual(headers.token, undefined, `id_token leaked to ${url}`);
    assert.strictEqual(headers.Authorization, undefined, `backend token leaked to ${url}`);
  }
  console.log('ok  no credentials leave for any other origin, path or scheme');

  const typedToken = await send(BACKEND + 'things', [['Token', 'mine-not-yours']]);
  assert.strictEqual(typedToken.Token, 'mine-not-yours');
  assert.ok(!('token' in typedToken), 'the id_token was added alongside a header typed by hand');
  console.log('ok  a token header typed into the form wins');

  const typedAuth = await send(BACKEND + 'things', [['Authorization', 'Basic something']]);
  assert.strictEqual(typedAuth.Authorization, 'Basic something');
  assert.strictEqual(typedAuth.token, ID_TOKEN, 'the id_token should be unaffected');
  console.log('ok  an Authorization header typed into the form wins on its own');

  // What the page shows about those headers.
  await fillIn(BACKEND + 'things');
  const shown = addedRows();
  assert.deepStrictEqual(shown.map(([name]) => name), ['Authorization', 'token']);
  assert.ok(!ids['added-headers'].hidden, 'the added rows should be visible');
  console.log('ok  both added headers are listed');

  const flat = shown.map(([, value]) => value).join(' ');
  assert.ok(!flat.includes(ID_TOKEN) && !flat.includes('backend-access-token'), `unmasked: ${flat}`);
  assert.ok(shown.every(([, value]) => value.includes('•')), `not masked: ${flat}`);
  assert.ok(shown[0][1].startsWith('Bearer •'), `scheme should stay readable: ${shown[0][1]}`);
  assert.ok(flat.includes(`(${ID_TOKEN.length} characters)`), `length should be shown: ${flat}`);
  console.log('ok  the values are masked, keeping only the scheme and the length');

  await fillIn('https://evil.example.com/api/things');
  assert.deepStrictEqual(addedRows(), [], 'nothing is added for another host');
  assert.ok(ids['added-headers'].hidden, 'so the block should be hidden');
  console.log('ok  nothing is listed for a URL outside the backend');

  await fillIn(BACKEND + 'things', [['token', 'mine-not-yours']]);
  assert.deepStrictEqual(addedRows().map(([name]) => name), ['Authorization']);
  console.log('ok  a header typed into the form drops out of the list');

  // Last, because replacing the document is one way: the shim has no elements afterwards.
  // A rejection here is the failure -- it is what "Cannot read properties of null" was.
  ids['replace-page'].checked = true;
  await send(BACKEND + 'things');
  await settle();
  assert.ok(replaced, 'the response should have replaced the document');
  console.log('ok  replacing the page leaves nothing reaching for the removed form');
})();

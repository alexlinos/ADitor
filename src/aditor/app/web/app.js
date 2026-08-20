/*
 * ADitor desktop app — the whole script. Vanilla, no framework, no build step.
 *
 * This file deliberately contains no rendering of data. Every fragment it puts
 * into the page was produced by aditor.app.render, in Python, with every value
 * escaped — see that module's docstring for why. The rule here is simple and
 * worth keeping: if a string came from the directory, this file does not build
 * markup out of it. It assigns a server-rendered fragment, or it uses
 * textContent.
 *
 * The password field is write-only. Nothing in this file ever reads it back
 * from the API, because the API never sends it.
 */

'use strict';

/* --- plumbing ------------------------------------------------------------ */

const el = (id) => document.getElementById(id);
const api = () => (window.pywebview && window.pywebview.api) || null;

/** Call a Python API method, surfacing a bridge failure rather than swallowing it. */
async function call(name, ...args) {
  const bridge = api();
  if (!bridge || typeof bridge[name] !== 'function') {
    throw new Error('The application bridge is not ready yet.');
  }
  return bridge[name](...args);
}

/** Put a Python-rendered fragment into a container. */
function paint(id, html) {
  const node = el(id);
  if (node) { node.innerHTML = html || ''; }
}

let toastTimer = null;
function toast(text) {
  const node = el('toast');
  if (!node) { return; }
  node.textContent = text;          // textContent: never markup from a message
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 3200);
}

function busy(button, isBusy, busyLabel) {
  if (!button) { return; }
  if (isBusy) {
    button.dataset.label = button.textContent;
    button.textContent = busyLabel || 'Working…';
    button.disabled = true;
  } else {
    if (button.dataset.label) { button.textContent = button.dataset.label; }
    button.disabled = false;
  }
}

/* --- navigation ---------------------------------------------------------- */

const SCREEN_LOADERS = {
  history: () => refreshHistory(),
  connect: () => refreshConnect(),
};

function show(screen) {
  document.querySelectorAll('.nav-item').forEach((item) => {
    const current = item.dataset.screen === screen;
    item.classList.toggle('is-current', current);
    item.setAttribute('aria-selected', current ? 'true' : 'false');
  });
  document.querySelectorAll('.screen').forEach((section) => {
    section.classList.toggle('is-current', section.id === 'screen-' + screen);
  });
  const loader = SCREEN_LOADERS[screen];
  if (loader) { loader(); }
}

/* --- 1. connection ------------------------------------------------------- */

function readForm() {
  return {
    server: el('f-server').value,
    domain: el('f-domain').value,
    base_dn: el('f-base-dn').value,
    bind_dn: el('f-bind-dn').value,
    password: el('f-password').value,
    validate_certificate: el('f-validate').checked,
    snapshot_dir: el('f-snapshot-dir').value,
  };
}

function applyState(state) {
  if (!state || !state.ok) { return; }
  const connection = state.connection || {};
  el('f-server').value = connection.server || '';
  el('f-domain').value = connection.domain || '';
  el('f-base-dn').value = connection.base_dn || '';
  el('f-bind-dn').value = connection.bind_dn || '';
  el('f-validate').checked = connection.validate_certificate !== false;
  el('f-snapshot-dir').value = connection.snapshot_dir || '';

  // The password itself never crosses the bridge. All the page learns is
  // whether one is available, so the field can say "leave blank to keep it".
  const hint = el('password-hint');
  if (hint && state.password_present) {
    hint.textContent = 'A password is already stored for this account in the '
      + 'operating system credential store. Leave this blank to keep it, or '
      + 'type a new one to replace it.';
  }
  paint('credential-store', (state.credential_store || {}).html);
  if (state.server) { paintServer(state.server); }
}

async function refreshState() {
  try {
    applyState(await call('state'));
  } catch (error) {
    toast(String(error.message || error));
  }
}

async function testConnection() {
  const button = el('btn-test');
  busy(button, true, 'Testing…');
  try {
    const result = await call('test_connection', readForm());
    paint('connection-result', result.html);
    toast(result.passed ? 'Connected.' : 'Connection failed — see below.');
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function saveConnection() {
  const button = el('btn-save');
  busy(button, true, 'Saving…');
  try {
    const result = await call('save_connection', readForm());
    paint('connection-result', result.html);
    if (result.ok) {
      el('f-password').value = '';     // no reason to keep it in the DOM
      applyState(result.state);
      toast('Saved.');
    }
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function forgetPassword() {
  try {
    const result = await call('forget_password');
    paint('connection-result', result.html);
    el('f-password').value = '';
    if (result.state) { applyState(result.state); }
  } catch (error) {
    toast(String(error.message || error));
  }
}

/* --- 2. scan ------------------------------------------------------------- */

let scanTimer = null;
let lastReportPath = '';

async function startScan() {
  const button = el('btn-scan');
  busy(button, true, 'Scanning…');
  el('btn-open-report').hidden = true;
  paint('scan-result', '');
  el('scan-progress').hidden = false;
  try {
    const started = await call('start_scan');
    if (!started.ok) {
      paint('scan-result', started.html);
      el('scan-progress').hidden = true;
      busy(button, false);
      return;
    }
    paint('scan-result', started.html);
    // Poll rather than have Python push: an evaluate_js from a worker thread is
    // exactly the sort of thing that works on one of pywebview's three
    // backends and not the other two.
    scanTimer = setInterval(pollScan, 400);
  } catch (error) {
    toast(String(error.message || error));
    el('scan-progress').hidden = true;
    busy(button, false);
  }
}

async function pollScan() {
  let update;
  try {
    update = await call('scan_progress');
  } catch (error) {
    return;                            // a dropped poll is not worth reporting
  }
  const progress = update.progress || {};
  el('scan-bar').value = progress.percent || 0;
  el('scan-message').textContent = progress.message || '';
  el('scan-elapsed').textContent = progress.elapsed_seconds
    ? progress.elapsed_seconds + 's elapsed'
    : '';

  if (!update.finished) { return; }
  clearInterval(scanTimer);
  scanTimer = null;
  busy(el('btn-scan'), false);
  paint('scan-result', update.html);
  lastReportPath = update.report_path || '';
  el('btn-open-report').hidden = !lastReportPath;
  toast(update.passed ? 'Scan complete.' : 'Scan failed.');
}

async function openLastReport() {
  if (!lastReportPath) { return; }
  try {
    const result = await call('open_path', lastReportPath);
    if (!result.ok) { toast(result.message); }
  } catch (error) {
    toast(String(error.message || error));
  }
}

/* --- 3. history ---------------------------------------------------------- */

async function refreshHistory() {
  try {
    const result = await call('history');
    paint('history-list', result.html);
  } catch (error) {
    toast(String(error.message || error));
  }
}

function selected(name) {
  const picked = document.querySelector('input[name="' + name + '"]:checked');
  return picked ? picked.value : '';
}

async function runDiff() {
  const button = el('btn-diff');
  const before = selected('diff-before');
  const after = selected('diff-after');
  if (!before || !after) {
    toast('Pick an earlier scan and a later scan.');
    return;
  }
  busy(button, true, 'Comparing…');
  try {
    const result = await call('diff', before, after);
    paint('diff-result', result.html);
    if (result.ok && result.attribution === 'ambiguous') {
      toast('Attribution is ambiguous — read the panel before reporting this.');
    }
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function openReport(folderName) {
  try {
    const result = await call('open_report', folderName);
    if (!result.ok) { toast(result.message); }
  } catch (error) {
    toast(String(error.message || error));
  }
}

/* --- 4. connect ---------------------------------------------------------- */

let snippetText = { claude_code: '', codex: '' };

function paintServer(server) {
  paint('server-status', server.status_html);
  paint('server-exposure', server.exposure_html);
  el('btn-start-server').disabled = !!server.running;
  el('btn-stop-server').disabled = !server.running;
}

async function refreshConnect() {
  try {
    const result = await call('connect_screen');
    paintServer(result.server || {});
    snippetText = result.snippets || snippetText;
    paint('snippets', result.html);
  } catch (error) {
    toast(String(error.message || error));
  }
}

async function serverAction(method, button, label) {
  busy(button, true, label);
  try {
    const result = await call(method);
    if (result.server) { paintServer(result.server); }
    if (!result.ok) { toast(result.message); }
    await refreshConnect();
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function copySnippet(key) {
  const text = snippetText[key] || '';
  if (!text) { return; }
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied. Paste it into your client config as-is — the URL has to keep '
          + 'its trailing slash.');
  } catch (error) {
    toast('Could not reach the clipboard. Select the snippet and copy it.');
  }
}

/* --- wiring -------------------------------------------------------------- */

function wire() {
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.addEventListener('click', () => show(item.dataset.screen));
  });

  el('btn-test').addEventListener('click', testConnection);
  el('btn-save').addEventListener('click', saveConnection);
  el('btn-forget').addEventListener('click', forgetPassword);

  el('btn-scan').addEventListener('click', startScan);
  el('btn-open-report').addEventListener('click', openLastReport);

  el('btn-refresh-history').addEventListener('click', refreshHistory);
  el('btn-diff').addEventListener('click', runDiff);

  el('btn-start-server').addEventListener('click', (event) =>
    serverAction('start_server', event.currentTarget, 'Starting…'));
  el('btn-stop-server').addEventListener('click', (event) =>
    serverAction('stop_server', event.currentTarget, 'Stopping…'));
  el('btn-refresh-server').addEventListener('click', refreshConnect);

  // Delegated: the buttons inside these panels are rendered by Python, so they
  // do not exist when this runs.
  document.addEventListener('click', (event) => {
    const opener = event.target.closest('[data-open-report]');
    if (opener) { openReport(opener.dataset.openReport); return; }
    const copier = event.target.closest('[data-copy]');
    if (copier) { copySnippet(copier.dataset.copy); }
  });
}

window.addEventListener('pywebviewready', () => {
  refreshState();
});

document.addEventListener('DOMContentLoaded', () => {
  wire();
  // pywebviewready may already have fired by the time the document parses.
  if (api()) { refreshState(); }
});

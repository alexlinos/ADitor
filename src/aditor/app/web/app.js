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

/* --- 1b. certificate and trust -------------------------------------------
 *
 * Note what is absent: there is no function here that trusts or installs a
 * certificate, because there is no bridge method to call. exportCa() and
 * downloadIssuer() ask Python to write a .crt file; copyCommand() puts text on
 * the clipboard. The operator runs the command. See
 * aditor/app/certificates.py for why that division is the whole point of this
 * panel.
 */

async function inspectCertificate() {
  const button = el('btn-inspect-cert');
  busy(button, true, 'Inspecting…');
  try {
    const result = await call('certificate_screen', readForm());
    paint('certificate-result', result.html);
    if (!result.ok) { toast(result.message); return; }
    // Three outcomes, three messages. "Could not check" never gets a
    // reassuring one.
    if (result.corroboration === 'disagree') {
      toast("Active Directory does not publish this chain's anchor. Read the "
            + 'warning before trusting anything.');
    } else if (result.corroboration === 'unavailable') {
      toast('The chain could not be checked against Active Directory. That is '
            + 'not a pass.');
    } else if (result.expiry_warning) {
      toast('A certificate here is expired or close to it — see the panel.');
    } else {
      toast('Chain read. Confirm the fingerprint before trusting it.');
    }
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function exportCa(fingerprint) {
  try {
    const result = await call('export_ca_certificate', fingerprint);
    paint('certificate-result', result.html);
    toast(result.ok
      ? 'Certificate written. ADitor has not installed it — run the command '
        + 'yourself once you have verified the fingerprint.'
      : result.message);
  } catch (error) {
    toast(String(error.message || error));
  }
}

/* Fetch the CA certificate that issued the controller's, and save it.
 *
 * Slow enough to need the busy state: it opens an LDAP connection and reads a
 * container. The button is rendered by Python, so it is passed in rather than
 * looked up by id.
 */
async function downloadIssuer(button) {
  busy(button, true, 'Fetching…');
  try {
    const result = await call('download_issuing_ca');
    if (result.html) { paint('certificate-result', result.html); }
    if (!result.ok) { toast(result.message); return; }
    toast('CA certificate saved. It signed the certificate the controller '
          + 'presented — now confirm the fingerprint with whoever runs the CA '
          + 'before you install it.');
  } catch (error) {
    toast(String(error.message || error));
  } finally {
    busy(button, false);
  }
}

async function copyCommand(text) {
  if (!text) { return; }
  try {
    await navigator.clipboard.writeText(text);
    toast('Command copied. Read it before you run it.');
  } catch (error) {
    toast('Could not reach the clipboard. Select the command and copy it.');
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

/* --- wiring -------------------------------------------------------------- */

function wire() {
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.addEventListener('click', () => show(item.dataset.screen));
  });

  el('btn-test').addEventListener('click', testConnection);
  el('btn-save').addEventListener('click', saveConnection);
  el('btn-forget').addEventListener('click', forgetPassword);
  el('btn-inspect-cert').addEventListener('click', inspectCertificate);

  el('btn-scan').addEventListener('click', startScan);
  el('btn-open-report').addEventListener('click', openLastReport);

  el('btn-refresh-history').addEventListener('click', refreshHistory);
  el('btn-diff').addEventListener('click', runDiff);

  // Delegated: the buttons inside these panels are rendered by Python, so they
  // do not exist when this runs.
  document.addEventListener('click', (event) => {
    const opener = event.target.closest('[data-open-report]');
    if (opener) { openReport(opener.dataset.openReport); return; }
    const exporter = event.target.closest('[data-export-ca]');
    if (exporter) { exportCa(exporter.dataset.exportCa); return; }
    const fetcher = event.target.closest('[data-download-issuer]');
    if (fetcher) { downloadIssuer(fetcher); return; }
    const commandCopier = event.target.closest('[data-copy-text]');
    if (commandCopier) { copyCommand(commandCopier.dataset.copyText); }
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

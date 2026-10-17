// URL Inspector frontend: plain DOM APIs, no framework.
//
// XSS safety: header values, certificate fields and URLs all come from
// EXTERNAL sites, so they could contain "<script>" or other HTML. We therefore
// build every element with document.createElement and put text in with
// textContent (or append(string), which also creates a text node). We never
// use innerHTML with any value from the response: the browser would parse it
// as HTML and could run an attacker's script on our page.

const form = document.getElementById('inspect-form');
const input = document.getElementById('url-input');
const button = document.getElementById('inspect-button');
const statusLine = document.getElementById('status');
const errorBox = document.getElementById('error');
const results = document.getElementById('results');

const PHASES = [
  { key: 'dns', label: 'DNS lookup' },
  { key: 'tcp', label: 'TCP connect' },
  { key: 'tls', label: 'TLS handshake' },
  { key: 'ttfb', label: 'Waiting (TTFB)' },
  { key: 'download', label: 'Download' },
];

const PHASE_NAMES = {
  validate: 'URL check',
  dns: 'DNS lookup',
  tcp: 'TCP connect',
  tls: 'TLS handshake',
  ttfb: 'waiting for the first byte',
  download: 'content download',
  redirect: 'following redirects',
};

// ---------- small DOM helpers ----------

// el('p', { className: 'muted' }, 'Hello ', someNode) -> <p class="muted">Hello …</p>
// Strings passed as children become text nodes, so they are never parsed as HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  if (props.className) node.className = props.className;
  if (props.text !== undefined) node.textContent = props.text;
  if (props.title) node.title = props.title;
  node.append(...children.filter((child) => child !== null && child !== undefined));
  return node;
}

function formatMs(ms) {
  return `${ms.toFixed(ms < 10 ? 1 : 0)} ms`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

// Adds "<dt>term</dt><dd>value</dd>" to a <dl>. value can be a string or a node.
function addDetail(list, term, value) {
  list.append(el('dt', { text: term }), el('dd', {}, value));
}

// ---------- 1. timing waterfall ----------

function renderWaterfall(data) {
  const container = document.getElementById('waterfall');
  container.replaceChildren();
  const t = data.timings;
  const total = t.total || 1; // avoid dividing by zero

  // The phases happen one after another, so each bar starts where the
  // previous one ended, like the DevTools Network tab.
  let start = 0;
  for (const phase of PHASES) {
    const ms = t[phase.key];
    let valueText = formatMs(ms);
    let applies = true;
    if (phase.key === 'dns' && data.dnsSkipped) [valueText, applies] = ['skipped', false];
    if (phase.key === 'tls' && !data.tls) [valueText, applies] = ['n/a (HTTP)', false];

    const bar = el('div', { className: `wf-bar bar-${phase.key}` });
    // Inline styles: offset and width are percentages of the total time.
    bar.style.left = `${(start / total) * 100}%`;
    bar.style.width = applies ? `${Math.max((ms / total) * 100, 0.5)}%` : '0'; // keep tiny phases visible

    container.append(
      el('div', { className: 'wf-row' },
        el('span', { text: phase.label }),
        el('div', { className: 'wf-track' }, bar),
        el('span', { className: 'wf-value', text: valueText }))
    );
    start += ms;
  }

  const totalBar = el('div', { className: 'wf-bar bar-total' });
  totalBar.style.left = '0%';
  totalBar.style.width = '100%';
  container.append(
    el('div', { className: 'wf-row wf-total' },
      el('span', { text: 'Total' }),
      el('div', { className: 'wf-track' }, totalBar),
      el('span', { className: 'wf-value', text: formatMs(t.total) }))
  );

  const hops = data.redirects.length - 1;
  const redirectMs = data.redirects.slice(0, -1).reduce((sum, hop) => sum + hop.ms, 0);
  document.getElementById('waterfall-note').textContent = hops > 0
    ? `These timings are for the final response. ${hops > 1 ? `The ${hops} redirects` : 'The redirect'} before it took ${formatMs(redirectMs)} more.`
    : 'Each request uses a brand-new connection, so every phase is measured.';
}

// ---------- 2. summary ----------

function renderSummary(data) {
  const list = document.getElementById('summary');
  list.replaceChildren();

  addDetail(list, 'Final URL', el('code', { text: data.finalUrl }));
  addDetail(list, 'Status', `${data.status.code} ${data.status.text}`);
  addDetail(list, 'Connected IP', el('code', { text: data.connectedIp }));

  const addresses = el('ul');
  for (const address of data.addresses) addresses.append(el('li', {}, el('code', { text: address })));
  addDetail(list, 'Resolved addresses', addresses);

  addDetail(list, 'Total time', formatMs(data.timings.total));
  addDetail(list, 'Body size',
    `${formatBytes(data.body.bytes)}${data.body.truncated ? ' (stopped reading at 1 MB)' : ''}`);
}

// ---------- 3. redirect chain ----------

function statusBadgeClass(code) {
  if (code >= 200 && code < 300) return 'badge good';
  if (code >= 300 && code < 400) return 'badge warn';
  return 'badge bad';
}

function renderRedirects(data) {
  const list = document.getElementById('redirects');
  list.replaceChildren();
  for (const hop of data.redirects) {
    list.append(
      el('li', {},
        el('span', { className: statusBadgeClass(hop.status), text: String(hop.status) }),
        el('code', { text: hop.url }),
        el('span', { className: 'muted small', text: ` · ${formatMs(hop.ms)}` }))
    );
  }
  const hops = data.redirects.length - 1;
  document.getElementById('redirects-note').textContent = hops === 0
    ? 'No redirects: the first response was the final one.'
    : `${hops} redirect${hops > 1 ? 's' : ''}. Every hop was checked against the private-IP block list.`;
}

// ---------- 4. certificate ----------

function renderCertificate(data) {
  const box = document.getElementById('certificate');
  box.replaceChildren();
  const cert = data.tls;

  if (!cert) {
    box.append(
      el('div', { className: 'badges' }, el('span', { className: 'badge bad', text: 'No TLS' })),
      el('p', { className: 'muted', text: 'This is plain HTTP, so there is no certificate. Anyone on the network path can read or change the traffic.' })
    );
    return;
  }

  const badges = el('div', { className: 'badges' });
  if (cert.authorized) badges.append(el('span', { className: 'badge good', text: 'Trusted' }));
  else badges.append(el('span', { className: 'badge bad', text: `Untrusted: ${cert.error || 'unknown reason'}` }));

  if (cert.daysUntilExpiry !== null && cert.daysUntilExpiry < 0) {
    badges.append(el('span', { className: 'badge bad', text: `Expired ${-cert.daysUntilExpiry} days ago` }));
  } else if (cert.daysUntilExpiry !== null && cert.daysUntilExpiry < 30) {
    badges.append(el('span', { className: 'badge warn', text: `Expires in ${cert.daysUntilExpiry} days` }));
  }

  const list = el('dl', { className: 'details' });
  addDetail(list, 'Subject (CN)', cert.subject || '—');
  addDetail(list, 'Issuer', [cert.issuer.organization, cert.issuer.commonName].filter(Boolean).join(' · ') || '—');
  addDetail(list, 'Valid from', cert.validFrom ? formatDate(cert.validFrom) : '—');
  addDetail(list, 'Valid to', cert.validTo ? formatDate(cert.validTo) : '—');
  addDetail(list, 'Days until expiry', cert.daysUntilExpiry === null ? '—' : String(cert.daysUntilExpiry));
  addDetail(list, 'Protocol', cert.protocol || '—');
  addDetail(list, 'Cipher', el('code', { text: cert.cipher || '—' }));

  const shown = cert.altNames.slice(0, 10);
  const more = cert.altNames.length - shown.length;
  addDetail(list, 'Alternative names',
    `${shown.join(', ') || '—'}${more > 0 ? ` and ${more} more` : ''}`);

  box.append(badges, list);
}

// ---------- 5. security grade ----------

function renderSecurity(data) {
  const box = document.getElementById('security');
  box.replaceChildren();
  const { score, grade, checks } = data.security;

  box.append(
    el('div', { className: 'grade-box' },
      el('div', { className: `grade grade-${grade}`, text: grade }),
      el('div', {},
        el('div', { className: 'check-name', text: `${score} / 100` }),
        el('div', { className: 'muted small', text: 'Based on six security headers in the final response.' })))
  );

  const list = el('ul', { className: 'checks' });
  for (const check of checks) {
    let icon = { symbol: '✗', className: 'bad', label: 'missing or invalid' };
    if (check.points === check.max) icon = { symbol: '✓', className: 'good', label: 'passed' };
    else if (check.points > 0) icon = { symbol: '~', className: 'warn', label: 'partial' };

    const body = el('div', { className: 'check-body' },
      check.present
        ? el('p', { className: 'check-value' }, el('code', { text: check.value }))
        : el('p', { className: 'muted', text: 'Not sent' }),
      check.note ? el('p', { className: 'muted', text: check.note }) : null,
      el('p', { text: check.explanation }));

    list.append(
      el('li', { className: 'check' },
        el('span', { className: `check-icon ${icon.className}`, text: icon.symbol, title: icon.label }),
        el('span', { className: 'check-name', text: check.header }),
        el('span', { className: 'check-points', text: `${check.points}/${check.max}` }),
        body)
    );
  }
  box.append(list);
}

// ---------- 6. response headers ----------

function renderHeaders(data) {
  const tbody = document.querySelector('#headers-table tbody');
  tbody.replaceChildren();
  const names = Object.keys(data.headers).sort();
  for (const name of names) {
    const value = data.headers[name];
    tbody.append(
      el('tr', {},
        el('td', { text: name }),
        el('td', {}, el('code', { text: Array.isArray(value) ? value.join('\n') : String(value) })))
    );
  }
}

// ---------- loading, errors and the request itself ----------

function setLoading(isLoading, url) {
  button.disabled = isLoading;
  for (const example of document.querySelectorAll('.example')) example.disabled = isLoading;
  button.textContent = isLoading ? 'Inspecting…' : 'Inspect';
  statusLine.classList.toggle('loading', isLoading);
  statusLine.textContent = isLoading ? `Inspecting ${url} (this can take up to 10 seconds)…` : '';
}

function showError(message, phase) {
  errorBox.replaceChildren(
    el('strong', { text: 'Inspection failed' }),
    el('p', { text: message }),
    phase ? el('p', { className: 'muted small', text: `Failed during: ${PHASE_NAMES[phase] || phase}` }) : null
  );
  errorBox.hidden = false;
}

async function runInspection(url) {
  errorBox.hidden = true;
  results.hidden = true;
  setLoading(true, url);

  // Put the URL in the address bar (?url=...) so the result can be shared.
  history.replaceState(null, '', `?url=${encodeURIComponent(url)}`);

  try {
    const response = await fetch(`/api/inspect?url=${encodeURIComponent(url)}`);
    const data = await response.json();

    if (!response.ok) {
      showError(data.error?.message || `Request failed (${response.status}).`, data.error?.phase);
      return;
    }

    renderWaterfall(data);
    renderSummary(data);
    renderRedirects(data);
    renderCertificate(data);
    renderSecurity(data);
    renderHeaders(data);
    results.hidden = false;
  } catch {
    showError('Could not reach the URL Inspector server. Is it running?');
  } finally {
    setLoading(false);
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault(); // stop the browser from reloading the page
  const url = input.value.trim();
  if (!url) {
    showError('Please enter a URL.');
    input.focus();
    return;
  }
  runInspection(url);
});

for (const example of document.querySelectorAll('.example')) {
  example.addEventListener('click', () => {
    input.value = example.dataset.url;
    runInspection(example.dataset.url);
  });
}

// If the page was opened with ?url=..., run it straight away.
const sharedUrl = new URLSearchParams(location.search).get('url');
if (sharedUrl) {
  input.value = sharedUrl;
  runInspection(sharedUrl);
}

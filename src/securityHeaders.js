// Scores a response's security headers out of 100.
// Pure function: it only looks at the headers object, so it is easy to unit test.

const HSTS_MIN_MAX_AGE = 15552000; // 180 days, in seconds

const EXPLANATIONS = {
  'strict-transport-security':
    'Without Strict-Transport-Security, an attacker on the same network (like public Wi-Fi) can downgrade the visit to plain HTTP and read or change the traffic.',
  'content-security-policy':
    'Without Content-Security-Policy, any script an attacker manages to inject into the page (XSS) will run, because the browser has no list of allowed sources.',
  'x-frame-options':
    'Without X-Frame-Options, another site can load this page in a hidden frame and trick users into clicking it (clickjacking).',
  'x-content-type-options':
    'Without X-Content-Type-Options: nosniff, the browser may guess a file\'s type and run an uploaded file as a script (MIME sniffing).',
  'referrer-policy':
    'Without Referrer-Policy, the full URL of this page, which can contain private IDs or tokens, may be sent to every site it links to.',
  'permissions-policy':
    'Without Permissions-Policy, the page and any frames inside it can ask for powerful features like the camera, microphone or location with no limits.',
};

// HTTP header names are case-insensitive, so lowercase every key first.
// Array values (a header sent more than once) are joined into one string.
function lowercaseHeaders(headers) {
  const result = {};
  for (const [name, value] of Object.entries(headers || {})) {
    result[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return result;
}

function check(header, max, value, points, note = null) {
  return {
    header,
    present: value !== undefined,
    value: value ?? null,
    points,
    max,
    explanation: EXPLANATIONS[header.toLowerCase()],
    note,
  };
}

function checkHsts(value, isHttps) {
  const name = 'Strict-Transport-Security';
  if (value === undefined) return check(name, 25, value, 0);
  if (!isHttps) return check(name, 25, value, 0, 'Browsers ignore HSTS on plain HTTP.');

  const match = value.match(/max-age\s*=\s*"?(\d+)"?/i);
  const maxAge = match ? Number(match[1]) : 0;
  if (maxAge >= HSTS_MIN_MAX_AGE) return check(name, 25, value, 25);
  return check(name, 25, value, 12.5, 'max-age is shorter than 180 days, so half points.');
}

function checkFrameOptions(value, csp) {
  const name = 'X-Frame-Options';
  const option = (value || '').trim().toUpperCase();
  if (option === 'DENY' || option === 'SAMEORIGIN') return check(name, 15, value, 15);

  // CSP frame-ancestors is the modern replacement for X-Frame-Options.
  if (csp && /frame-ancestors/i.test(csp)) {
    return check(name, 15, value, 15, 'Protected by the CSP frame-ancestors directive instead.');
  }
  if (value !== undefined) return check(name, 15, value, 0, 'Value must be DENY or SAMEORIGIN.');
  return check(name, 15, value, 0);
}

function checkNoSniff(value) {
  const name = 'X-Content-Type-Options';
  if (value === undefined) return check(name, 15, value, 0);
  if (value.trim().toLowerCase() === 'nosniff') return check(name, 15, value, 15);
  return check(name, 15, value, 0, 'Value must be "nosniff".');
}

function checkPresent(name, max, value) {
  return check(name, max, value, value === undefined ? 0 : max);
}

export function gradeFor(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export function scoreHeaders(headers, isHttps) {
  const h = lowercaseHeaders(headers);
  const csp = h['content-security-policy'];

  const checks = [
    checkHsts(h['strict-transport-security'], isHttps),
    checkPresent('Content-Security-Policy', 25, csp),
    checkFrameOptions(h['x-frame-options'], csp),
    checkNoSniff(h['x-content-type-options']),
    checkPresent('Referrer-Policy', 10, h['referrer-policy']),
    checkPresent('Permissions-Policy', 10, h['permissions-policy']),
  ];

  // Round because half-point HSTS (12.5) can leave a .5 in the total.
  const score = Math.round(checks.reduce((sum, c) => sum + c.points, 0));
  return { score, grade: gradeFor(score), checks };
}

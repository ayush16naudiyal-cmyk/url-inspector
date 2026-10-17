import dns from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { InspectorError } from './errors.js';
import { isPrivateIp, privateHostsAllowed } from './ipGuard.js';
import { normalizeUrl } from './validateUrl.js';
import { scoreHeaders } from './securityHeaders.js';

const MAX_BODY_BYTES = 1024 * 1024; // read at most 1 MB of the body

// process.hrtime.bigint() is a nanosecond clock that only moves forward.
// Date.now() is only millisecond-precise and can jump if the system clock changes.
const now = () => process.hrtime.bigint();
const msBetween = (start, end) => Math.round(Number(end - start) / 1e5) / 10; // ns -> ms, 1 decimal

// Readable messages for the network errors people actually hit.
const NETWORK_ERRORS = {
  ECONNREFUSED: 'The server refused the connection (nothing is listening on that port).',
  ECONNRESET: 'The server closed the connection unexpectedly.',
  ETIMEDOUT: 'The connection timed out.',
  EHOSTUNREACH: 'The server is unreachable from here.',
  ENETUNREACH: 'The network is unreachable from here.',
  EPROTO: 'The TLS handshake failed (the server may not speak HTTPS on this port).',
};

const TLS_ERRORS = {
  CERT_HAS_EXPIRED: 'The certificate has expired.',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'The certificate is self-signed.',
  SELF_SIGNED_CERT_IN_CHAIN: 'The certificate chain contains a self-signed certificate.',
  ERR_TLS_CERT_ALTNAME_INVALID: 'The certificate does not match this hostname.',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'The certificate is not signed by a trusted authority.',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'The certificate is not signed by a trusted authority.',
};

// Step 1: DNS. Turn the hostname into IP addresses, then run the SSRF check.
// We time this lookup ourselves and later pin the connection to the IP we
// checked here (see the `lookup` option in requestOnce).
export async function resolveHost(url) {
  // new URL() keeps IPv6 hosts in brackets ("[::1]"); dns and net want them bare.
  const host = url.hostname.replace(/^\[|\]$/g, '');

  let addresses;
  let dnsMs = 0;
  const dnsSkipped = net.isIP(host) !== 0;

  if (dnsSkipped) {
    // The user typed an IP address, so there is nothing to look up.
    addresses = [{ address: host, family: net.isIP(host) }];
  } else {
    const start = now();
    try {
      // all: true returns every A (IPv4) and AAAA (IPv6) record, not just the first.
      addresses = await dns.promises.lookup(host, { all: true });
    } catch (err) {
      throw new InspectorError(`Could not find "${host}". The DNS lookup failed (${err.code}).`, {
        phase: 'dns',
      });
    }
    dnsMs = msBetween(start, now());
  }

  if (!privateHostsAllowed()) {
    const blocked = addresses.find((a) => isPrivateIp(a.address));
    if (blocked) {
      const what = dnsSkipped ? host : `${host} points to ${blocked.address}, which`;
      throw new InspectorError(`Blocked: ${what} is a private or internal address.`, {
        status: 400,
        phase: 'dns',
      });
    }
  }

  // Prefer IPv4: many servers (including some cloud hosts) have no IPv6 route out.
  const chosen = addresses.find((a) => a.family === 4) || addresses[0];

  return {
    host,
    ip: chosen.address,
    family: chosen.family,
    addresses: addresses.map((a) => a.address),
    dnsMs,
    dnsSkipped,
  };
}

function describeCertificate(socket) {
  const cert = socket.getPeerCertificate();
  const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
  const errorCode = socket.authorizationError ? String(socket.authorizationError) : null;

  return {
    subject: cert.subject?.CN ?? null,
    altNames: cert.subjectaltname
      ? cert.subjectaltname.split(', ').map((name) => name.replace(/^DNS:/, ''))
      : [],
    issuer: {
      organization: cert.issuer?.O ?? null,
      commonName: cert.issuer?.CN ?? null,
    },
    validFrom: cert.valid_from ? new Date(cert.valid_from).toISOString() : null,
    validTo: validTo ? validTo.toISOString() : null,
    daysUntilExpiry: validTo ? Math.floor((validTo - Date.now()) / 86_400_000) : null,
    protocol: socket.getProtocol(), // e.g. "TLSv1.3"
    cipher: socket.getCipher()?.name ?? null,
    // authorized is false if the chain isn't trusted OR the hostname doesn't match.
    authorized: socket.authorized,
    error: errorCode ? TLS_ERRORS[errorCode] || errorCode : null,
    errorCode,
  };
}

// Work out which phase we were in when something went wrong.
function phaseAt(marks, isHttps) {
  if (!marks.connect) return 'tcp';
  if (isHttps && !marks.secureConnect) return 'tls';
  if (!marks.firstByte) return 'ttfb';
  return 'download';
}

// Steps 2-5: one HTTP(S) request to the IP from resolveHost, timing each phase.
// It never follows redirects; it just reports the status and Location header.
// `signal` lets inspect() abort the request on timeout; `progress` lets it see
// which phase we were in at that moment.
export function requestOnce(url, target, { signal, progress = {} } = {}) {
  const isHttps = url.protocol === 'https:';
  const client = isHttps ? https : http;
  const marks = { start: now() };
  progress.marks = marks;
  progress.isHttps = isHttps;

  return new Promise((resolve, reject) => {
    const req = client.request({
      signal, // when aborted, Node destroys the socket and the request errors
      hostname: target.host, // sent in the Host header
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'User-Agent': 'URL-Inspector/1.0 (+learning project)',
        Accept: '*/*',
        // Ask for an uncompressed body so the byte count is simple and honest.
        'Accept-Encoding': 'identity',
      },

      // agent: false means "no connection pool": Node opens a brand new socket
      // for this request. With keep-alive reuse, a second request would skip
      // DNS, TCP and TLS entirely and those timings would be 0.
      agent: false,

      // DNS rebinding protection: instead of letting Node look the name up
      // again (and maybe get a different, internal IP), hand back the IP we
      // already resolved and checked. Node 20+ may ask for a list (all: true).
      lookup: (hostname, options, callback) => {
        if (options.all) callback(null, [{ address: target.ip, family: target.family }]);
        else callback(null, target.ip, target.family);
      },

      // SNI: tells the server which site's certificate we want. SNI must be a
      // hostname, so it is left out when the user typed an IP address.
      servername: net.isIP(target.host) ? undefined : target.host,

      // Accept bad certificates so we can still INSPECT them (expired,
      // self-signed, wrong host). This is safe here because we only read the
      // response and never send passwords, cookies or other secrets. We always
      // check and report socket.authorized below.
      rejectUnauthorized: false,
    });

    req.on('socket', (socket) => {
      socket.on('connect', () => {
        marks.connect = now(); // TCP three-way handshake finished
      });
      socket.on('secureConnect', () => {
        marks.secureConnect = now(); // TLS handshake finished
        marks.tls = describeCertificate(socket);
      });
    });

    req.on('response', (res) => {
      // 'response' fires as soon as the status line and headers have arrived,
      // which is the first data the server sends back: our "first byte".
      marks.firstByte = now();
      const connectedIp = res.socket.remoteAddress;
      let bytes = 0;
      let truncated = false;

      const finish = () => {
        marks.end = now();
        const connected = marks.connect;
        const handshakeDone = marks.secureConnect || connected;
        req.destroy(); // make sure the socket is closed
        resolve({
          url: url.href,
          connectedIp,
          status: { code: res.statusCode, text: res.statusMessage },
          headers: res.headers,
          location: res.headers.location ?? null,
          timings: {
            tcp: msBetween(marks.start, connected),
            tls: isHttps ? msBetween(connected, marks.secureConnect) : 0,
            ttfb: msBetween(handshakeDone, marks.firstByte),
            download: msBetween(marks.firstByte, marks.end),
            request: msBetween(marks.start, marks.end), // everything after DNS
          },
          tls: isHttps ? marks.tls : null,
          body: { bytes, truncated },
        });
      };

      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes >= MAX_BODY_BYTES && !truncated) {
          // Stop reading: we only need the size, not a huge download.
          truncated = true;
          finish();
        }
      });
      res.on('end', () => {
        if (!truncated) finish();
      });
      res.on('error', (err) => reject(networkError(err, 'download')));
    });

    req.on('error', (err) => reject(networkError(err, phaseAt(marks, isHttps))));
    req.end(); // send the request (a GET has no body)
  });
}

function networkError(err, phase) {
  if (err instanceof InspectorError) return err;
  const message = NETWORK_ERRORS[err.code] || err.message;
  return new InspectorError(message, { phase });
}

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 10_000;

const round1 = (n) => Math.round(n * 10) / 10;

// Follow redirects by hand, one hop at a time. Doing it manually (instead of
// an auto-follow option) lets us time every hop and re-run the SSRF check on
// each new host: a public URL can redirect to http://127.0.0.1/.
async function followRedirects(startUrl, { signal, progress }) {
  const chain = [];
  const visited = new Set();
  let url = startUrl;

  while (true) {
    if (visited.has(url.href)) {
      throw new InspectorError(`Redirect loop: ${url.href} appears twice in the chain.`, {
        phase: 'redirect',
      });
    }
    visited.add(url.href);

    progress.marks = null; // back in the DNS phase for this hop
    let target;
    try {
      target = await resolveHost(url); // SSRF check runs again for every hop
    } catch (err) {
      if (chain.length > 0) {
        err.message = `${err.message.replace(/\.$/, '')}, reached by a redirect from ${chain.at(-1).url}.`;
      }
      throw err;
    }
    const response = await requestOnce(url, target, { signal, progress });
    const hopMs = round1(target.dnsMs + response.timings.request);

    chain.push({
      url: url.href,
      status: response.status.code,
      statusText: response.status.text,
      location: response.location,
      ms: hopMs,
    });

    // Not a redirect (or a redirect with no Location): this is the final response.
    if (!REDIRECT_CODES.has(response.status.code) || !response.location) {
      return { chain, target, response, url };
    }

    if (chain.length > MAX_REDIRECTS) {
      throw new InspectorError(`Too many redirects (more than ${MAX_REDIRECTS}).`, {
        phase: 'redirect',
      });
    }

    // Location can be relative ("/login"), so resolve it against the current URL.
    let next;
    try {
      next = new URL(response.location, url);
    } catch {
      throw new InspectorError(`The server redirected to an invalid URL: ${response.location}`, {
        phase: 'redirect',
      });
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      throw new InspectorError(`The server redirected to an unsupported URL: ${next.href}`, {
        phase: 'redirect',
      });
    }
    url = next;
  }
}

// Inspect a URL: validate it, follow redirects, and describe the final response.
// Timings, certificate, headers and the score are all for the FINAL response;
// `redirects` lists every hop, including the final one.
export async function inspect(input, { timeoutMs = TIMEOUT_MS } = {}) {
  const startUrl = normalizeUrl(input);

  // One deadline for the whole inspection, across every hop. Aborting the
  // controller destroys whatever socket is open, so nothing is left hanging.
  const controller = new AbortController();
  const progress = { marks: null, isHttps: false };
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      const phase = progress.marks ? phaseAt(progress.marks, progress.isHttps) : 'dns';
      controller.abort();
      reject(new InspectorError(`Timed out after ${timeoutMs / 1000} seconds.`, { phase }));
    }, timeoutMs);
  });

  let result;
  try {
    result = await Promise.race([
      followRedirects(startUrl, { signal: controller.signal, progress }),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }

  const { chain, target, response, url } = result;
  const isHttps = url.protocol === 'https:';

  return {
    input,
    finalUrl: url.href,
    addresses: target.addresses,
    connectedIp: response.connectedIp,
    dnsSkipped: target.dnsSkipped,
    timings: {
      dns: target.dnsMs,
      tcp: response.timings.tcp,
      tls: response.timings.tls,
      ttfb: response.timings.ttfb,
      download: response.timings.download,
      total: round1(target.dnsMs + response.timings.request),
    },
    status: response.status,
    redirects: chain,
    tls: response.tls,
    headers: response.headers,
    security: scoreHeaders(response.headers, isHttps),
    body: response.body,
  };
}

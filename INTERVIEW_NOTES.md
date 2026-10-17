# Interview notes: URL Inspector

Simple-English notes for explaining this project and the networking behind it. Line numbers point to the code as committed.

---

## 1. "What happens when you type a URL into the browser?"

Say it as a story, one step at a time. For each step, say what my tool does there.

| # | Step | What happens | Where my code does or measures it |
|---|---|---|---|
| 1 | **Parse the URL** | The browser splits `https://example.com/path` into scheme, host, port and path. If you type `example.com`, it guesses `https://`. | `normalizeUrl()` in [src/validateUrl.js:15](src/validateUrl.js) adds `https://`, allows only http/https, and parses with `new URL()`. |
| 2 | **Check HSTS / caches** | If the site sent HSTS before (or is on the preload list), the browser goes straight to HTTPS. It may also answer from its HTTP cache. | Not done: my tool never caches, so every run is a fresh, full request. HSTS is *graded* in `scoreHeaders()`. |
| 3 | **DNS lookup** | Turn the hostname into an IP address (see section 2). | `resolveHost()` [src/inspector.js:39](src/inspector.js). It is timed around `dns.promises.lookup(host, { all: true })` at line 54. Every address is checked by `isPrivateIp` at line 64. |
| 4 | **TCP connect** | Three-way handshake (SYN → SYN-ACK → ACK) to port 443 or 80 (see section 3). | Timer starts when the request is created (`marks.start`) and stops on the socket's `connect` event, [src/inspector.js:172](src/inspector.js). |
| 5 | **TLS handshake** | HTTPS only: agree on keys and check the server's certificate (see section 4). | Stops on the socket's `secureConnect` event at line 175. The certificate is read by `describeCertificate()` (`getPeerCertificate()` at line 88, `socket.authorized` at line 107). |
| 6 | **Send the HTTP request** | `GET /path HTTP/1.1`, a `Host` header and other headers (see section 5). | `client.request({...})` and `req.end()` at line 226. |
| 7 | **Server works on it** | A web server (nginx, Apache or a Node/Express app) receives the request, maybe passes it through a reverse proxy or CDN, runs code, reads a database, and builds the response. | This time is inside **TTFB**. |
| 8 | **First byte arrives (TTFB)** | The status line and headers come back first. | The `response` event at line 183 marks the first byte. TTFB = first byte − end of handshake (line 202). |
| 9 | **Download the body** | The rest of the HTML arrives in chunks. | `res.on('data')` counts bytes and stops at 1 MB (line 215). `end` stops the timer (line 189). Download = end − first byte (line 203). |
| 10 | **Redirect?** | A 3xx with `Location` means "go to this other URL instead", and the browser starts again from step 1. | `followRedirects()`: the loop check at line 251, the SSRF re-check at line 261, relative `Location` resolved at line 293, the 10-hop limit at line 284. |
| 11 | **Parse HTML → DOM** | The browser reads the HTML and builds the DOM tree. It reads CSS into the CSSOM, and the two combine into a render tree. | Not done by the tool. But my own frontend builds the DOM directly with `document.createElement` ([public/app.js:39](public/app.js)), which is what the parser does for HTML. |
| 12 | **Load subresources, run JS** | `<link>`, `<script>` and `<img>` each start their own request (steps 3–9 again, often on reused connections). JavaScript runs and can change the DOM. | Not done: the tool inspects only the main document. |
| 13 | **Layout and paint** | The browser works out the size and position of every box (layout), draws pixels (paint), and composites the layers onto the screen. | Not done. |

**One-sentence version:** "The browser parses the URL, looks up the IP with DNS, opens a TCP connection, does a TLS handshake for HTTPS, sends an HTTP request, the web server builds a response, the browser receives the headers and body, follows any redirect, then parses the HTML into the DOM and renders the page. My tool measures every network step up to the end of the download."

---

## 2. DNS explained

- **Why:** computers connect to IP addresses, but people remember names.
- **Who asks whom:**
  1. The browser and the OS check their own **cache** first.
  2. If there's no answer, the OS asks a **recursive resolver**: usually your ISP's, or a public one like 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare).
  3. If the resolver has no cached answer, it walks the tree:
     - It asks a **root server**: "who handles `.com`?" The root gives the **TLD servers** for `.com`.
     - It asks the **TLD server**: "who handles `example.com`?" The TLD gives the domain's **authoritative name servers**.
     - It asks the **authoritative server**: "what is the IP of `example.com`?" This server gives the real answer.
  4. The resolver sends the answer back to the OS and **caches** it.
- **Record types:** an **A** record maps a name to an **IPv4** address (`93.184.215.14`). An **AAAA** record maps a name to an **IPv6** address (`2606:2800:…`). A **CNAME** is an alias that points one name at another name.
- **TTL (time to live):** every answer says how many seconds it may be cached. A long TTL means fewer lookups. A short TTL means changes spread faster.
- **What my tool sees:** only the final OS lookup (`dns.lookup` uses the OS resolver, `getaddrinfo`). If the answer was cached, DNS shows about 1 ms. If the resolver had to walk root → TLD → authoritative, it shows tens or hundreds of ms. The tool cannot see the individual steps.

---

## 3. TCP three-way handshake

1. Client → server: **SYN** ("I want to connect; my starting sequence number is X").
2. Server → client: **SYN-ACK** ("OK; mine is Y, and I got your X").
3. Client → server: **ACK** ("got your Y").

- **Why it costs one round trip:** the client must wait for the SYN-ACK to come back before it can send anything useful. The ACK can travel together with the first data, so the cost is one RTT (round-trip time). From India to a server in the US that is about 200–250 ms before a single byte of HTTP is sent.
- **Why TCP does it:** both sides agree on sequence numbers, so TCP can deliver bytes **in order** and **resend lost packets**.
- **Story from building this:** on my machine, TCP sometimes took exactly ~1 s, ~3 s or ~7 s. I checked with a plain `net.connect` and the same thing happened. Those are Windows' SYN retransmission waits (1 s, then 2 s more, then 4 s more) after a lost SYN packet, so my tool was showing a real network problem.

---

## 4. TLS handshake explained

**Goal:** (1) prove the server really is `example.com`, and (2) agree on a secret key that only the two sides know, so the traffic can be encrypted.

**TLS 1.3 steps:**
1. **ClientHello**: the client sends the TLS versions and cipher suites it supports, a random number, its **key share** (its half of a Diffie-Hellman exchange), and **SNI** (the hostname it wants).
2. **ServerHello**: the server picks the version and cipher and sends its own key share. Both sides can now work out the **same shared secret** (ECDHE: elliptic-curve Diffie-Hellman), even though the secret itself never crossed the network.
3. The server sends its **certificate**, a **signature** made with its private key (proving it owns that certificate), and **Finished**. From here on everything is encrypted.
4. The client checks the certificate and signature, then sends **Finished**. Application data (the HTTP request) can now flow.

**Certificate chain and certificate authorities (CAs):**
- The server's certificate says "this public key belongs to `example.com`" and is **signed by an intermediate CA**. The intermediate is signed by a **root CA**.
- The OS and browser ship with a list of trusted root CAs. The client checks every signature up the chain to one of those roots.
- It also checks the **dates** (valid from / valid to) and that the **hostname** matches the subject or the subject alternative names.
- If any check fails, `socket.authorized` is `false` and `authorizationError` says why: `CERT_HAS_EXPIRED`, `DEPTH_ZERO_SELF_SIGNED_CERT` or `ERR_TLS_CERT_ALTNAME_INVALID`. My tool turns these into readable messages (the `TLS_ERRORS` map in `src/inspector.js`).

**Why asymmetric for the key, symmetric for the data:**
- **Asymmetric** cryptography (public/private keys, Diffie-Hellman, signatures) lets two strangers agree on a secret and prove identity without meeting first. But it is **slow**.
- **Symmetric** cryptography (AES-GCM, ChaCha20) is **very fast** but needs both sides to already share a key.
- So TLS uses asymmetric crypto once, to authenticate and agree on a key, then switches to symmetric crypto for all the data.

**TLS 1.2 vs 1.3:**

| | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Round trips before data | **2** | **1** (0 on resumption with 0-RTT) |
| Why | Hello messages first, then key exchange in a second trip | The client sends its key share in the very first message |
| Key exchange | RSA key transport or (EC)DHE | Only (EC)DHE, which gives forward secrecy |
| Old weak ciphers | Still allowed | Removed |

**SNI (Server Name Indication):** one IP address can host many HTTPS sites, so the client says which hostname it wants inside the ClientHello, and the server picks the right certificate. In my code: `servername: target.host` at [src/inspector.js:161](src/inspector.js). It is left out for raw IPs, because SNI must be a hostname.

---

## 5. HTTP

**A request on the wire** (what my tool sends):
```
GET /path?q=1 HTTP/1.1
Host: example.com
User-Agent: URL-Inspector/1.0 (+learning project)
Accept: */*
Accept-Encoding: identity
Connection: close

```
(It ends with an empty line. A GET has no body.)

**A response:**
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 1256
Strict-Transport-Security: max-age=31536000

<!doctype html><html>...
```
It has a status line, headers, an empty line, then the body.

**Status code classes:**

| Class | Meaning | Examples |
|---|---|---|
| 1xx | Informational | 101 Switching Protocols |
| 2xx | Success | 200 OK, 204 No Content |
| 3xx | Redirection | 301, 302, 304 Not Modified |
| 4xx | Client error | 400 Bad Request, 401, 403, 404, 429 Too Many Requests |
| 5xx | Server error | 500, 502 Bad Gateway, 503, 504 |

**301 vs 302 vs 307 vs 308:**

| Code | Permanent? | Keeps the method (POST stays POST)? |
|---|---|---|
| 301 Moved Permanently | Yes, browsers and search engines remember it | Not guaranteed (old browsers switched POST to GET) |
| 302 Found | No, temporary | Not guaranteed (same problem) |
| 303 See Other | No | No, always changes to GET (used after a form POST) |
| 307 Temporary Redirect | No | **Yes** |
| 308 Permanent Redirect | Yes | **Yes** |

My tool only sends GET, so all five are followed the same way.

**Why my tool uses HTTP/1.1 while browsers use HTTP/2 or HTTP/3:**
- Node's `http` and `https` modules only speak **HTTP/1.1**. HTTP/2 needs the separate `http2` module.
- Browsers agree on **HTTP/2** during the TLS handshake (ALPN). HTTP/2 sends many requests at once over one connection, as binary frames with compressed headers.
- **HTTP/3** runs over **QUIC** (on UDP). QUIC combines the transport and TLS 1.3 handshakes, so a new connection takes about 1 RTT instead of 2 (TCP + TLS).
- So my numbers are a faithful **HTTP/1.1** picture. A browser may connect faster, especially with HTTP/3.

**Web servers:** a web server (nginx, Apache, Caddy, or Node itself) listens on a port, parses HTTP, and either serves files or passes the request to application code. Often there is a **reverse proxy** or **CDN** in front (Cloudflare, Render's load balancer) that handles TLS and caching. My own app is Express, which serves `public/` as static files and `/api/*` as routes.

---

## 6. Each security header in two lines

- **Strict-Transport-Security (HSTS):** stops **SSL-stripping / downgrade attacks**, where someone on public Wi-Fi keeps you on plain HTTP. It tells the browser "only ever use HTTPS for this site, for `max-age` seconds." My tool gives full points at ≥ 180 days and 0 on plain HTTP, because browsers ignore it there.
- **Content-Security-Policy (CSP):** limits the damage of **XSS**. It lists where scripts, styles and images may load from, so an injected `<script>` from somewhere else won't run.
- **X-Frame-Options:** stops **clickjacking**, where another site loads you in an invisible iframe and tricks users into clicking. `DENY` or `SAMEORIGIN` blocks this. CSP `frame-ancestors` is the modern version, so my tool accepts either.
- **X-Content-Type-Options: nosniff:** stops **MIME sniffing**, where the browser guesses that an uploaded "image" is really a script and runs it. With `nosniff` it trusts the `Content-Type`.
- **Referrer-Policy:** stops **leaking URLs** (which may contain IDs or reset tokens) to other sites through the `Referer` header when users click links. For example, `strict-origin-when-cross-origin` sends only the domain.
- **Permissions-Policy:** stops the page, or **ads and iframes inside it**, from using the camera, microphone, location and so on. For example, `camera=()` turns the camera off for everyone.

---

## 7. Security of my own tool

- **SSRF (Server-Side Request Forgery):** my server fetches whatever URL the user types. Without protection, someone could type `http://169.254.169.254/latest/meta-data/` (the cloud metadata service, which can expose credentials) or `http://localhost:6379` and make **my server** reach machines only it can see. Fix: after DNS, `isPrivateIp()` ([src/ipGuard.js:59](src/ipGuard.js)) refuses loopback, private, link-local, CGNAT and reserved ranges, for IPv4 and IPv6. That includes `::ffff:127.0.0.1`, which is 127.0.0.1 written in IPv6 form.
- **Why I re-check on every redirect:** the first URL can be public and harmless, then answer `302 Location: http://127.0.0.1/admin`. If I only checked the first URL, the redirect would get around the block. I tested this with httpbin's redirect endpoint, and it gets blocked.
- **DNS rebinding:** an attacker controls a domain's DNS. The first lookup (the one I check) returns a public IP; a second lookup a moment later returns `127.0.0.1`. If the HTTP client did its own lookup, it could connect to the internal IP. Fix: I pass a custom `lookup` function ([src/inspector.js:154](src/inspector.js)) that hands back **the exact IP I already checked**. The `Host` header and SNI still use the real hostname, so the site works normally.
- **Why `textContent` and not `innerHTML`:** header values and certificate fields come from **any website**, so an attacker can make their server send `X-Evil: <img src=x onerror=alert(document.cookie)>`. With `innerHTML` the browser would parse that as HTML and run the script on *my* page (stored or reflected XSS). `textContent` always treats it as plain text. I tested exactly this payload: it shows as text and no `<img>` element is created.
- **Rate limiting:** each inspection opens outbound connections, so without a limit someone could use my server to flood other sites, or run up my hosting bill. 20 requests per minute per IP with `express-rate-limit` ([src/app.js:26](src/app.js)). `trust proxy` is 1 (line 16), so behind Render's proxy I limit the **real client IP**, not the proxy's IP (which would put every user in one shared bucket).
- **Timeouts:** a server that accepts the connection and never answers would tie up my server forever. One 10-second deadline covers the whole inspection, and `AbortController.abort()` ([src/inspector.js:322](src/inspector.js)) destroys the socket. The 1 MB body cap stops someone pointing it at a huge file.

---

## 8. Three design choices

- **Why `agent: false`** ([src/inspector.js:149](src/inspector.js)): Node normally keeps a pool of open connections (keep-alive) and reuses them. A reused connection skips DNS, TCP and TLS, so those phases would show 0 and the measurement would be wrong. `agent: false` forces a brand-new socket every time, which matches a first visit.
- **Why `process.hrtime.bigint()`** (line 14): it is a **monotonic** clock (it never jumps backwards if the system clock is corrected) with **nanosecond** precision. `Date.now()` has only millisecond precision and can jump, so it can give wrong or even negative durations for phases that take under 1 ms.
- **Why `rejectUnauthorized: false` is acceptable here** (line 167): normally you must reject bad certificates, or a man-in-the-middle could read what you send. My tool **sends no secrets**: no passwords, cookies or tokens, just a plain GET. It only reads headers. Accepting the bad certificate lets me **show** the user what is wrong (expired, self-signed, wrong host) instead of just failing. I still always check `socket.authorized` and show "Untrusted" in red. In a normal app that sends data, this setting would be a serious vulnerability.

---

## 9. 15 likely interview questions

1. **Why build networking with `dns`/`net`/`tls`/`https` instead of axios or fetch?**
   Those libraries hide the phases. With the low-level modules I can attach to socket events (`connect`, `secureConnect`) and time each step myself.

2. **How do you measure TTFB exactly?**
   From the end of the handshake (`secureConnect`, or `connect` for HTTP) to the `response` event, which fires when the status line and headers arrive. It covers the request travelling over, the server's work, and the first bytes travelling back.

3. **Why is the DNS time sometimes 1 ms and sometimes 80 ms?**
   Caching. A cached answer in the OS or resolver is nearly instant. A cold lookup means the resolver walks root → TLD → authoritative.

4. **Why is TLS 1.3 faster than 1.2?**
   The client sends its key share in the first message, so the handshake takes 1 round trip instead of 2.

5. **What does `socket.authorized === false` mean?**
   The certificate failed verification: an untrusted chain (for example self-signed), expired, or a hostname mismatch. `authorizationError` gives the reason.

6. **What is SSRF and how did you prevent it?**
   Tricking a server into making requests to internal addresses. I resolve DNS first, block private and reserved IPs, re-check on every redirect, and pin the connection to the checked IP.

7. **What is DNS rebinding?**
   A domain whose DNS answer changes between the check and the connection. I avoid it by connecting to the exact IP I validated, using a custom `lookup` function.

8. **Why follow redirects manually?**
   So I can time each hop, record the chain, detect loops, and run the SSRF check on every new host. Auto-follow would hide all of that.

9. **How do you detect a redirect loop?**
   I keep a `Set` of visited URLs. If the next URL is already in it, I stop with an error. I also cap the chain at 10 redirects for chains that never repeat but never end.

10. **How do you handle a relative `Location` like `/login`?**
    `new URL(location, currentUrl)` resolves it against the current URL, the same way a browser does.

11. **How is the security score calculated, and why is it a pure function?**
    Fixed weights (HSTS 25, CSP 25, XFO 15, XCTO 15, Referrer 10, Permissions 10), with HSTS partial credit. It's pure (headers in, score out, no network), so unit tests can feed it any headers.

12. **How did you test networking without the internet?**
    The tests start a local `http` server on a random port (port 0) that returns known headers, a 301 → 302 → 200 chain, a loop, a 2 MB body and a request that never answers. `ALLOW_PRIVATE_HOSTS=true` lets the tests reach 127.0.0.1.

13. **Why not use `innerHTML`? Isn't it faster to write?**
    The data comes from untrusted sites. `innerHTML` would parse attacker-controlled HTML and could run scripts (XSS). `createElement` plus `textContent` cannot.

14. **Why `app.set('trust proxy', 1)`?**
    Behind Render's proxy, every request seems to come from the proxy's IP. Trusting one hop makes Express read the real client IP from `X-Forwarded-For`, so the rate limit works per user.

15. **Why would your timings differ from Chrome DevTools?**
    My server measures from its own location (a Render region), uses HTTP/1.1, opens a fresh connection every time and has no cache. Chrome uses your network, may use HTTP/2 or HTTP/3, and reuses connections and cached DNS.

**Bonus quick ones:**
- *What does 502 mean in your API?* "Bad Gateway": my server is fine, but the site it tried to reach failed (DNS, connection refused, timeout, loop).
- *Why `Accept-Encoding: identity`?* It asks for an uncompressed body, so the byte count is honest and I don't need decompression code.
- *Why prefer IPv4?* Some servers and cloud hosts have no outbound IPv6 route, and connecting to an IPv6 address would fail.

---

## 10. Limitations and what I'd add next

**Limitations now**
- HTTP/1.1 only, so it doesn't show HTTP/2 or HTTP/3 behaviour.
- One measurement from one location: the server's region, not the user's.
- DNS time is only the final OS lookup. Resolver steps are invisible.
- Connects to one address. There is no IPv4/IPv6 racing ("Happy Eyeballs") like browsers do.
- Main document only. No subresources (CSS, JS, images) and no rendering.
- GET only, no cookies, uncompressed body.
- The rate limiter lives in memory, so it resets on restart and doesn't work across several servers.

**What I'd add next**
1. **HTTP/2 support** using Node's `http2` module, picking the protocol through ALPN and showing which one was used.
2. **Measure from several regions** (small workers in the US, EU and Asia) and show the timings side by side, so geography and CDNs become visible.
3. **Compare two URLs** side by side (for example `www` vs non-`www`, or before vs after a deploy).
4. Run each URL 3–5 times and show the median, to smooth out network noise like the SYN retransmits I saw.
5. Show the full certificate chain (intermediate and root), not just the leaf certificate.
6. Store the rate limit in Redis so it works across several instances.

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import rateLimit from 'express-rate-limit';
import { inspect } from './inspector.js';
import { InspectorError } from './errors.js';

// ES modules have no __dirname, so we rebuild it from this file's URL.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

// Behind proxies, req.socket's address is the proxy's, not the user's, so ALL
// users would share one rate limit. Each proxy appends the address it got the
// request from to X-Forwarded-For. On Render we measured three hops:
//   X-Forwarded-For: <client>, <Cloudflare edge>, <Render load balancer>
//   socket address:  ::1 (a local proxy in front of our app)
// Trusting exactly 3 hops makes req.ip the real client. We don't trust more,
// because anything further left can be typed in by the client (spoofed).
app.set('trust proxy', 3);

// Serve index.html, styles.css and app.js from the public/ folder.
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Each inspection makes outbound connections, so limit how often one IP can ask.
const inspectLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  limit: 20, // 20 requests per IP per minute
  standardHeaders: 'draft-7', // send a RateLimit header so clients can see their quota
  legacyHeaders: false,
  handler: (req, res) => {
    res.status(429).json({
      error: { message: 'Too many requests. Please wait a minute and try again.' },
    });
  },
});

app.get('/api/inspect', inspectLimiter, async (req, res) => {
  const { url } = req.query;

  // ?url=a&url=b would give an array; only accept a single string.
  if (typeof url !== 'string' || !url.trim()) {
    return res.status(400).json({ error: { message: 'Please provide a URL, e.g. /api/inspect?url=example.com' } });
  }

  try {
    res.json(await inspect(url));
  } catch (err) {
    if (err instanceof InspectorError) {
      return res.status(err.status).json({ error: { message: err.message, phase: err.phase } });
    }
    // A bug on our side: log it, but don't leak details to the user.
    console.error(err);
    res.status(500).json({ error: { message: 'Something went wrong on our side.' } });
  }
});

// Exported without calling listen() so tests can import the app directly.
export default app;

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';

// ES modules have no __dirname, so we rebuild it from this file's URL.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

// Serve index.html, styles.css and app.js from the public/ folder.
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Exported without calling listen() so tests can import the app directly.
export default app;

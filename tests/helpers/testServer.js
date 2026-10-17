import http from 'node:http';

// A tiny local HTTP server for tests, so no test depends on the real internet.
export const SECURE_HEADERS = {
  'Strict-Transport-Security': 'max-age=31536000',
  'Content-Security-Policy': "default-src 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=()',
};

export function startTestServer() {
  const server = http.createServer((req, res) => {
    const { pathname, searchParams } = new URL(req.url, 'http://localhost');
    const base = `http://127.0.0.1:${server.address().port}`;
    const redirect = (code, location) => {
      res.writeHead(code, { Location: location });
      res.end();
    };

    switch (pathname) {
      case '/secure':
        res.writeHead(200, { ...SECURE_HEADERS, 'Content-Type': 'text/plain' });
        res.end('hello world');
        break;
      case '/start': // 301 with a RELATIVE Location
        redirect(301, '/middle');
        break;
      case '/middle': // 302 with an ABSOLUTE Location
        redirect(302, `${base}/secure`);
        break;
      case '/loop-a':
        redirect(302, '/loop-b');
        break;
      case '/loop-b':
        redirect(302, '/loop-a');
        break;
      case '/forever': { // never-ending chain of different URLs
        const n = Number(searchParams.get('n') || 0);
        redirect(302, `/forever?n=${n + 1}`);
        break;
      }
      case '/big': // 2 MB body, to test the 1 MB cap
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(Buffer.alloc(2 * 1024 * 1024));
        break;
      case '/hang': // never answers, to test the timeout
        break;
      default:
        res.writeHead(404);
        res.end('not found');
    }
  });

  return new Promise((resolve) => {
    // Port 0 = let the OS pick a free port.
    server.listen(0, '127.0.0.1', () => {
      resolve({
        base: `http://127.0.0.1:${server.address().port}`,
        close: () => {
          server.closeAllConnections(); // also drops the /hang connection
          return new Promise((done) => server.close(done));
        },
      });
    });
  });
}

// A port with nothing listening on it, to test "connection refused".
export function getClosedPort() {
  return new Promise((resolve) => {
    const server = http.createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

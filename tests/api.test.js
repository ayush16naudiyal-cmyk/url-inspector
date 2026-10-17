import request from 'supertest';
import app from '../src/app.js';
import { startTestServer } from './helpers/testServer.js';

let server;

beforeAll(async () => {
  server = await startTestServer();
});

afterAll(async () => {
  delete process.env.ALLOW_PRIVATE_HOSTS;
  await server.close();
});

describe('GET /api/health', () => {
  test('returns ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('GET /api/inspect', () => {
  test('400 when the url is missing', async () => {
    const res = await request(app).get('/api/inspect');
    expect(res.status).toBe(400);
    expect(res.body.error.message).toEqual(expect.any(String));
  });

  test('400 for an unsupported scheme', async () => {
    const res = await request(app).get('/api/inspect').query({ url: 'ftp://example.com' });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/Only http/);
  });

  test('400 for a private IP when ALLOW_PRIVATE_HOSTS is off', async () => {
    process.env.ALLOW_PRIVATE_HOSTS = 'false';
    const res = await request(app).get('/api/inspect').query({ url: `${server.base}/secure` });
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/Blocked/);
  });

  test('400 for the cloud metadata address', async () => {
    process.env.ALLOW_PRIVATE_HOSTS = 'false';
    const res = await request(app).get('/api/inspect').query({ url: 'http://169.254.169.254/latest/meta-data/' });
    expect(res.status).toBe(400);
    expect(res.body.error.phase).toBe('dns');
  });

  test('200 with the full result shape for the local server', async () => {
    process.env.ALLOW_PRIVATE_HOSTS = 'true';
    const res = await request(app).get('/api/inspect').query({ url: `${server.base}/start` });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      input: `${server.base}/start`,
      finalUrl: `${server.base}/secure`,
      addresses: ['127.0.0.1'],
      connectedIp: '127.0.0.1',
      timings: {
        dns: expect.any(Number),
        tcp: expect.any(Number),
        tls: expect.any(Number),
        ttfb: expect.any(Number),
        download: expect.any(Number),
        total: expect.any(Number),
      },
      status: { code: 200, text: 'OK' },
      tls: null,
      headers: expect.objectContaining({ 'x-content-type-options': 'nosniff' }),
      security: { score: 75, grade: 'B', checks: expect.any(Array) },
      body: { bytes: 11, truncated: false },
    });
    expect(res.body.redirects).toHaveLength(3);
    expect(res.body.security.checks[0]).toEqual(
      expect.objectContaining({
        header: 'Strict-Transport-Security',
        present: true,
        points: 0,
        max: 25,
        explanation: expect.any(String),
      })
    );
  });

  test('502 with the failing phase on a redirect loop', async () => {
    process.env.ALLOW_PRIVATE_HOSTS = 'true';
    const res = await request(app).get('/api/inspect').query({ url: `${server.base}/loop-a` });
    expect(res.status).toBe(502);
    expect(res.body.error).toEqual({
      message: expect.stringContaining('Redirect loop'),
      phase: 'redirect',
    });
  });
});

import { inspect } from '../src/inspector.js';
import { startTestServer, getClosedPort } from './helpers/testServer.js';

let server;

beforeAll(async () => {
  // The test server runs on 127.0.0.1, which the SSRF guard would block.
  process.env.ALLOW_PRIVATE_HOSTS = 'true';
  server = await startTestServer();
});

afterAll(async () => {
  delete process.env.ALLOW_PRIVATE_HOSTS;
  await server.close();
});

describe('inspect() against a local server', () => {
  test('follows a 301 -> 302 -> 200 redirect chain', async () => {
    const result = await inspect(`${server.base}/start`);

    expect(result.redirects.map((hop) => hop.status)).toEqual([301, 302, 200]);
    expect(result.redirects[0].location).toBe('/middle'); // relative Location kept as sent
    expect(result.redirects[1].url).toBe(`${server.base}/middle`); // ...and resolved correctly
    expect(result.redirects[2].location).toBeNull();
    expect(result.finalUrl).toBe(`${server.base}/secure`);
    expect(result.status).toEqual({ code: 200, text: 'OK' });
  });

  test('returns the final response headers and scores them', async () => {
    const result = await inspect(`${server.base}/start`);

    expect(result.headers['x-frame-options']).toBe('DENY');
    expect(result.headers['content-type']).toBe('text/plain');
    // Plain HTTP, so HSTS earns 0 and the rest earn 75.
    expect(result.security.score).toBe(75);
    expect(result.security.grade).toBe('B');
  });

  test('timings are numbers, and DNS is skipped for an IP host', async () => {
    const result = await inspect(`${server.base}/secure`);

    for (const phase of ['dns', 'tcp', 'tls', 'ttfb', 'download', 'total']) {
      expect(typeof result.timings[phase]).toBe('number');
      expect(result.timings[phase]).toBeGreaterThanOrEqual(0);
    }
    expect(result.dnsSkipped).toBe(true);
    expect(result.timings.dns).toBe(0);
    expect(result.tls).toBeNull(); // plain HTTP has no certificate
    expect(result.connectedIp).toBe('127.0.0.1');
    expect(result.body).toEqual({ bytes: 11, truncated: false });
    for (const hop of result.redirects) expect(typeof hop.ms).toBe('number');
  });

  test('stops with a clear error on a redirect loop', async () => {
    await expect(inspect(`${server.base}/loop-a`)).rejects.toMatchObject({
      phase: 'redirect',
      status: 502,
      message: expect.stringContaining('Redirect loop'),
    });
  });

  test('stops after 10 redirects', async () => {
    await expect(inspect(`${server.base}/forever`)).rejects.toMatchObject({
      phase: 'redirect',
      message: expect.stringContaining('Too many redirects'),
    });
  });

  test('reads at most 1 MB of the body and marks it truncated', async () => {
    const result = await inspect(`${server.base}/big`);
    expect(result.body.truncated).toBe(true);
    expect(result.body.bytes).toBeGreaterThanOrEqual(1024 * 1024);
    expect(result.body.bytes).toBeLessThan(2 * 1024 * 1024);
  });

  test('times out a server that never answers, and reports the phase', async () => {
    await expect(inspect(`${server.base}/hang`, { timeoutMs: 300 })).rejects.toMatchObject({
      phase: 'ttfb',
      message: expect.stringContaining('Timed out'),
    });
  });

  test('reports connection refused in the tcp phase', async () => {
    const port = await getClosedPort();
    await expect(inspect(`http://127.0.0.1:${port}/`)).rejects.toMatchObject({
      phase: 'tcp',
      status: 502,
    });
  });
});

import request from 'supertest';
import app from '../src/app.js';

// Its own file, so it gets a fresh rate limiter and doesn't affect api.test.js.
test('the 21st /api/inspect request in a minute gets a 429', async () => {
  // Requests with no url fail fast with 400, but still count toward the limit.
  for (let i = 0; i < 20; i++) {
    const res = await request(app).get('/api/inspect');
    expect(res.status).toBe(400);
  }

  const res = await request(app).get('/api/inspect');
  expect(res.status).toBe(429);
  expect(res.body.error.message).toMatch(/Too many requests/);
});

test('/api/health is not rate limited', async () => {
  const res = await request(app).get('/api/health');
  expect(res.status).toBe(200);
});

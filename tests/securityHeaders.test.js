import { scoreHeaders, gradeFor } from '../src/securityHeaders.js';

const ALL_GOOD = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
};

// Small helper: find one header's check in the result.
const checkFor = (result, header) => result.checks.find((c) => c.header === header);

describe('scoreHeaders', () => {
  test('all headers present gives 100 and an A', () => {
    const result = scoreHeaders(ALL_GOOD, true);
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A');
    expect(result.checks).toHaveLength(6);
  });

  test('no headers gives 0 and an F, with an explanation for each', () => {
    const result = scoreHeaders({}, true);
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
    for (const c of result.checks) {
      expect(c.present).toBe(false);
      expect(c.explanation).toEqual(expect.any(String));
    }
  });

  test('HSTS with max-age under 180 days gets half points', () => {
    const result = scoreHeaders({ 'strict-transport-security': 'max-age=86400' }, true);
    expect(checkFor(result, 'Strict-Transport-Security').points).toBe(12.5);
  });

  test('HSTS on plain HTTP gets 0 points', () => {
    const result = scoreHeaders(ALL_GOOD, false);
    const hsts = checkFor(result, 'Strict-Transport-Security');
    expect(hsts.present).toBe(true);
    expect(hsts.points).toBe(0);
    expect(result.score).toBe(75);
  });

  test('CSP frame-ancestors counts for X-Frame-Options', () => {
    const result = scoreHeaders({ 'content-security-policy': "frame-ancestors 'none'" }, true);
    expect(checkFor(result, 'X-Frame-Options').points).toBe(15);
  });

  test('X-Content-Type-Options must be exactly nosniff', () => {
    const result = scoreHeaders({ 'x-content-type-options': 'sniff-please' }, true);
    expect(checkFor(result, 'X-Content-Type-Options').points).toBe(0);
  });

  test('header names are matched case-insensitively', () => {
    const mixedCase = {
      'Strict-Transport-Security': 'max-age=31536000',
      'CONTENT-SECURITY-POLICY': "default-src 'self'",
      'X-Frame-Options': 'sameorigin',
      'X-CONTENT-TYPE-OPTIONS': 'NoSniff',
      'Referrer-Policy': 'no-referrer',
      'Permissions-Policy': 'geolocation=()',
    };
    expect(scoreHeaders(mixedCase, true).score).toBe(100);
  });
});

describe('gradeFor', () => {
  test.each([
    [100, 'A'], [90, 'A'], [89, 'B'], [75, 'B'], [60, 'C'], [40, 'D'], [39, 'F'],
  ])('%i -> %s', (score, grade) => {
    expect(gradeFor(score)).toBe(grade);
  });
});

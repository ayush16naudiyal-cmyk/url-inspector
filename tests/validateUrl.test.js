import { normalizeUrl } from '../src/validateUrl.js';

describe('normalizeUrl', () => {
  test('adds https:// when no scheme is typed', () => {
    expect(normalizeUrl('example.com').href).toBe('https://example.com/');
  });

  test('keeps an http:// URL as it is', () => {
    expect(normalizeUrl('http://neverssl.com').href).toBe('http://neverssl.com/');
  });

  test('treats host:port without a scheme as a host, not a scheme', () => {
    expect(normalizeUrl('example.com:8080/path').href).toBe('https://example.com:8080/path');
  });

  test.each(['ftp://example.com', 'javascript:alert(1)', 'file:///etc/passwd'])(
    'rejects %s with a 400 error',
    (input) => {
      expect(() => normalizeUrl(input)).toThrow(/Only http/);
      try {
        normalizeUrl(input);
      } catch (err) {
        expect(err.status).toBe(400);
      }
    }
  );

  test.each(['', '   ', undefined])('rejects empty input %p', (input) => {
    expect(() => normalizeUrl(input)).toThrow('Please enter a URL.');
  });

  test('rejects text that cannot be parsed as a URL', () => {
    expect(() => normalizeUrl('http://')).toThrow(/not a valid URL/);
  });
});

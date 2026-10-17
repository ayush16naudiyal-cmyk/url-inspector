import { InspectorError } from './errors.js';

// Matches a scheme at the start, like "https:" or "javascript:".
// The (?!\d) part stops "example.com:8080" from being read as scheme "example.com".
const SCHEME_PATTERN = /^([a-z][a-z0-9+.-]*):(?!\d)/i;

function invalid(message) {
  return new InspectorError(message, { status: 400, phase: 'validate' });
}

// Turns what the user typed into a safe URL object, or throws a 400 error.
//   "example.com"          -> https://example.com/
//   "http://neverssl.com"  -> http://neverssl.com/
//   "ftp://x", "javascript:alert(1)", ""  -> error
export function normalizeUrl(input) {
  const text = String(input ?? '').trim();
  if (!text) throw invalid('Please enter a URL.');

  const scheme = text.match(SCHEME_PATTERN);
  if (scheme && !['http', 'https'].includes(scheme[1].toLowerCase())) {
    throw invalid(`Only http:// and https:// URLs are supported (got "${scheme[1]}:").`);
  }

  // No scheme typed: assume https, like the browser address bar does today.
  const withScheme = scheme ? text : `https://${text}`;

  let url;
  try {
    url = new URL(withScheme);
  } catch {
    throw invalid(`"${text}" is not a valid URL.`);
  }

  // Double check after parsing, in case the parser saw something we didn't.
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw invalid('Only http:// and https:// URLs are supported.');
  }
  if (!url.hostname) throw invalid('The URL has no hostname.');

  return url;
}

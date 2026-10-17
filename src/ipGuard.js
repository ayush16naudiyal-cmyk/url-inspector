import net from 'node:net';

// SSRF protection: our server fetches any URL a user types, so without this
// check someone could make it fetch http://127.0.0.1/admin or the cloud
// metadata service at 169.254.169.254 and read things only the server can see.

// IPv4 ranges we refuse to connect to: [base address, prefix length, reason].
const BLOCKED_IPV4_RANGES = [
  ['0.0.0.0', 8, '"this network"'],
  ['10.0.0.0', 8, 'private network'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback (this machine)'],
  ['169.254.0.0', 16, 'link-local, includes cloud metadata 169.254.169.254'],
  ['172.16.0.0', 12, 'private network'],
  ['192.168.0.0', 16, 'private network'],
];

// "93.184.215.14" -> one 32-bit number, so ranges can be compared with bit masks.
function ipv4ToNumber(ip) {
  return ip.split('.').reduce((total, part) => total * 256 + Number(part), 0);
}

function isInIpv4Range(ip, base, prefixLength) {
  // A /12 mask keeps the first 12 bits: 11111111 11110000 00000000 00000000.
  // ">>> 0" turns JavaScript's signed 32-bit result back into an unsigned one.
  const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
  return ((ipv4ToNumber(ip) & mask) >>> 0) === ((ipv4ToNumber(base) & mask) >>> 0);
}

function isPrivateIpv4(ip) {
  return BLOCKED_IPV4_RANGES.some(([base, prefix]) => isInIpv4Range(ip, base, prefix));
}

function isPrivateIpv6(ip) {
  // The same IPv6 address can be written many ways (::1 = 0:0:0:0:0:0:0:1).
  // The URL parser rewrites it into one short, lowercase form for us.
  const canonical = new URL(`http://[${ip}]`).hostname.slice(1, -1);

  if (canonical === '::1' || canonical === '::') return true; // loopback / unspecified

  // IPv4-mapped IPv6 (::ffff:127.0.0.1) reaches the IPv4 address inside it,
  // so check that IPv4 address too. The parser writes it as ::ffff:7f00:1.
  const mapped = canonical.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped) {
    const high = parseInt(mapped[1], 16);
    const low = parseInt(mapped[2], 16);
    const ipv4 = [high >> 8, high & 255, low >> 8, low & 255].join('.');
    return isPrivateIpv4(ipv4);
  }

  // Look at the first 16 bits ("fe80" in fe80::1). "::..." starts with zeros.
  const firstGroup = canonical.startsWith('::') ? 0 : parseInt(canonical.split(':')[0], 16);
  if ((firstGroup & 0xfe00) === 0xfc00) return true; // fc00::/7  unique local (private)
  if ((firstGroup & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  return false;
}

// Pure function: no DNS, no network. Returns true if we must NOT connect to `ip`.
export function isPrivateIp(ip) {
  // Drop an IPv6 zone like "fe80::1%eth0"; it doesn't change which range it is in.
  const address = String(ip).split('%')[0];
  const version = net.isIP(address);
  if (version === 4) return isPrivateIpv4(address);
  if (version === 6) return isPrivateIpv6(address);
  // Not a valid IP at all: fail closed (treat it as blocked) to be safe.
  return true;
}

// The ALLOW_PRIVATE_HOSTS=true flag turns the check off. It exists ONLY so
// tests can talk to a local server on 127.0.0.1. Never set it in production.
export function privateHostsAllowed() {
  return process.env.ALLOW_PRIVATE_HOSTS === 'true';
}

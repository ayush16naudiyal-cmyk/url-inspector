import { isPrivateIp } from '../src/ipGuard.js';

describe('isPrivateIp', () => {
  test.each([
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', '10.0.0.0/8'],
    ['172.16.0.1', 'start of 172.16.0.0/12'],
    ['172.31.255.255', 'end of 172.16.0.0/12'],
    ['192.168.1.1', '192.168.0.0/16'],
    ['169.254.169.254', 'cloud metadata address'],
    ['0.0.0.0', '0.0.0.0/8'],
    ['100.64.0.1', 'carrier-grade NAT'],
    ['::1', 'IPv6 loopback'],
    ['fd12:3456::1', 'IPv6 unique local (fc00::/7)'],
    ['fe80::1', 'IPv6 link-local'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
  ])('blocks %s (%s)', (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  test.each([
    ['8.8.8.8'],
    ['172.32.0.1'], // just outside 172.16.0.0/12
    ['93.184.215.14'],
    ['2606:4700:4700::1111'],
  ])('allows public address %s', (ip) => {
    expect(isPrivateIp(ip)).toBe(false);
  });

  test('treats something that is not an IP as blocked', () => {
    expect(isPrivateIp('not-an-ip')).toBe(true);
  });
});

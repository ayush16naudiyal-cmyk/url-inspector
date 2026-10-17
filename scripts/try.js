// Try the inspector from the command line, without the API or the browser:
//   node scripts/try.js github.com
//   node scripts/try.js http://neverssl.com --json
import { inspect } from '../src/inspector.js';

const [input, flag] = process.argv.slice(2);
if (!input) {
  console.log('Usage: node scripts/try.js <url> [--json]');
  process.exit(1);
}

try {
  const result = await inspect(input);

  if (flag === '--json') {
    console.log(JSON.stringify(result, null, 2));
  } else {
    const t = result.timings;
    console.log(`\n${result.finalUrl}  ->  ${result.status.code} ${result.status.text}`);
    console.log(`Connected to ${result.connectedIp}  (resolved: ${result.addresses.join(', ')})\n`);

    console.log('Timings (ms)');
    console.log(`  DNS lookup     ${t.dns}${result.dnsSkipped ? '  (skipped: host is an IP)' : ''}`);
    console.log(`  TCP connect    ${t.tcp}`);
    console.log(`  TLS handshake  ${t.tls}${result.tls ? '' : '  (plain HTTP)'}`);
    console.log(`  TTFB           ${t.ttfb}`);
    console.log(`  Download       ${t.download}`);
    console.log(`  Total          ${t.total}\n`);

    if (result.tls) {
      const c = result.tls;
      console.log('Certificate');
      console.log(`  Subject   ${c.subject}`);
      console.log(`  Issuer    ${c.issuer.organization} (${c.issuer.commonName})`);
      console.log(`  Valid     ${c.validFrom} -> ${c.validTo}  (${c.daysUntilExpiry} days left)`);
      console.log(`  TLS       ${c.protocol}, ${c.cipher}`);
      console.log(`  Trusted   ${c.authorized ? 'yes' : `NO: ${c.error}`}`);
      console.log(`  Alt names ${c.altNames.slice(0, 5).join(', ')}${c.altNames.length > 5 ? ', ...' : ''}\n`);
    }

    console.log(`Security headers: ${result.security.score}/100 (${result.security.grade})`);
    for (const c of result.security.checks) {
      console.log(`  ${c.points === c.max ? 'OK ' : '-- '} ${c.header.padEnd(26)} ${c.points}/${c.max}`);
    }
    console.log(`\nBody: ${result.body.bytes} bytes${result.body.truncated ? ' (truncated at 1 MB)' : ''}`);
  }
} catch (err) {
  console.error(`Failed${err.phase ? ` during "${err.phase}"` : ''}: ${err.message}`);
  process.exitCode = 1;
}

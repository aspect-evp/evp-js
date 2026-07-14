import { DNS_RECORD_PREFIX } from '@aspect-evp/core';
import { defaultDnsResolver, nodeDnsResolver } from '@aspect-evp/verifier';
import { defineCommand } from 'citty';
import consola from 'consola';
import pc from 'picocolors';
import {
  formatError,
  formatHeader,
  formatJson,
  formatSuccess,
  formatTable,
  symbols,
} from '../utils/format.js';

export const dnsCommand = defineCommand({
  meta: {
    name: 'dns',
    description: 'Lookup EVP DNS records for a domain',
  },
  args: {
    domain: {
      type: 'positional',
      description: 'Email domain to lookup (e.g., gmail.com)',
      required: true,
    },
    resolver: {
      type: 'string',
      alias: 'r',
      description: 'DNS resolver to use (doh, node)',
      default: 'doh',
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    const domain = args.domain as string;
    const recordName = `${DNS_RECORD_PREFIX}.${domain}`;

    consola.start(`Looking up EVP record for ${domain}...`);

    const resolver = args.resolver === 'node' ? nodeDnsResolver : defaultDnsResolver;
    const resolverName = args.resolver === 'node' ? 'Node.js DNS' : 'DNS-over-HTTPS (Cloudflare)';

    try {
      const issuer = await resolver(domain);

      if (args.json) {
        console.log(
          formatJson({
            domain,
            recordName,
            resolver: resolverName,
            found: !!issuer,
            issuer: issuer || null,
          })
        );
        return;
      }

      console.log();

      if (issuer) {
        console.log(formatSuccess(`EVP record found for ${domain}`));
        console.log();
        console.log(
          formatTable([
            ['Domain', domain],
            ['Record', recordName],
            ['Resolver', resolverName],
            ['Issuer', issuer],
          ])
        );

        console.log();
        console.log(formatHeader('What this means'));
        console.log(`  ${symbols.bullet} This domain supports EVP email verification`);
        console.log(`  ${symbols.bullet} Tokens should be issued by: ${pc.cyan(issuer)}`);
        console.log(
          `  ${symbols.bullet} Metadata endpoint: ${pc.cyan(`https://${issuer}/.well-known/email-verification`)}`
        );
      } else {
        console.log(formatError(`No EVP record found for ${domain}`));
        console.log();
        console.log(
          formatTable([
            ['Domain', domain],
            ['Record', recordName],
            ['Resolver', resolverName],
          ])
        );

        console.log();
        console.log(formatHeader('What this means'));
        console.log(`  ${symbols.bullet} This domain does not publish an EVP DNS record`);
        console.log(`  ${symbols.bullet} The email provider may not support EVP yet`);
        console.log();
        console.log(pc.dim('Expected DNS record format:'));
        console.log(pc.dim(`  TXT ${recordName} "iss=issuer.example.com"`));
      }
    } catch (error) {
      if (args.json) {
        console.log(
          formatJson({
            domain,
            recordName,
            resolver: resolverName,
            found: false,
            error: error instanceof Error ? error.message : String(error),
          })
        );
        process.exit(1);
      }

      console.log();
      console.log(formatError('DNS lookup failed'));
      consola.error(error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  },
});

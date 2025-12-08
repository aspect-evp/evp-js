import * as fs from 'node:fs';
import { EmailVerificationIssuer } from '@aspect-evp/issuer';
import { defineCommand } from 'citty';
import consola from 'consola';
import { formatHeader, formatJson, formatSuccess, formatTable, truncate } from '../utils/format.js';

export const issueCommand = defineCommand({
  meta: {
    name: 'issue',
    description: 'Issue an EVP token for testing',
  },
  args: {
    email: {
      type: 'string',
      alias: 'e',
      description: 'Email address to issue token for',
      required: true,
    },
    issuer: {
      type: 'string',
      alias: 'i',
      description: 'Issuer identifier (domain)',
      required: true,
    },
    key: {
      type: 'string',
      alias: 'k',
      description: 'Path to private key JSON file',
      required: true,
    },
    algorithm: {
      type: 'string',
      alias: 'a',
      description: 'Signing algorithm',
      default: 'EdDSA',
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    // Read private key
    let privateKey: JsonWebKey;
    try {
      const keyContent = fs.readFileSync(args.key, 'utf-8');
      privateKey = JSON.parse(keyContent);
    } catch (_error) {
      consola.error(`Failed to read private key from ${args.key}`);
      process.exit(1);
    }

    // biome-ignore lint/complexity/useLiteralKeys: TypeScript requires bracket notation for index signatures
    const kid = ((privateKey as Record<string, unknown>)['kid'] as string) || 'default';

    consola.start(`Issuing token for ${args.email}...`);

    // Create issuer
    const issuer = new EmailVerificationIssuer({
      issuer: args.issuer,
      privateKey,
      kid,
      algorithm: args.algorithm as 'EdDSA' | 'ES256' | 'ES384' | 'RS256',
    });

    // Generate a temporary browser key for testing
    const browserKeyPair = await EmailVerificationIssuer.generateKeyPair('ES256');

    // Issue token
    const sdJwt = await issuer.issueToken(args.email, browserKeyPair.publicKey);

    if (args.json) {
      console.log(
        formatJson({
          email: args.email,
          issuer: args.issuer,
          sdJwt,
          browserPublicKey: browserKeyPair.publicKey,
          browserPrivateKey: browserKeyPair.privateKey,
        })
      );
      return;
    }

    console.log();
    console.log(formatSuccess('Token issued successfully'));
    console.log();
    console.log(
      formatTable([
        ['Email', args.email],
        ['Issuer', args.issuer],
        ['Algorithm', args.algorithm],
        ['Key ID', kid],
      ])
    );

    console.log();
    console.log(formatHeader('SD-JWT Token'));
    console.log(truncate(sdJwt, 100));
    console.log();
    console.log(formatHeader('Full Token'));
    console.log(sdJwt);

    console.log();
    console.log(formatHeader('Browser Key Pair (for creating KB-JWT)'));
    console.log(formatJson(browserKeyPair));

    console.log();
    consola.info('Use the browser private key to create a Key Binding JWT for verification.');
  },
});

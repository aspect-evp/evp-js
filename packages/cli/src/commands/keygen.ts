import { EmailVerificationIssuer } from '@aspect-evp/issuer';
import { defineCommand } from 'citty';
import consola from 'consola';
import { formatHeader, formatJson, formatSuccess, formatTable } from '../utils/format.js';

export const keygenCommand = defineCommand({
  meta: {
    name: 'keygen',
    description: 'Generate a new key pair for EVP token signing',
  },
  args: {
    algorithm: {
      type: 'string',
      alias: 'a',
      description: 'Signing algorithm (EdDSA, ES256, ES384, RS256)',
      default: 'EdDSA',
    },
    kid: {
      type: 'string',
      alias: 'k',
      description: 'Key ID for the generated key pair',
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    const algorithm = args.algorithm as 'EdDSA' | 'ES256' | 'ES384' | 'RS256';
    const validAlgorithms = ['EdDSA', 'ES256', 'ES384', 'RS256'];

    if (!validAlgorithms.includes(algorithm)) {
      consola.error(
        `Invalid algorithm: ${algorithm}. Valid options: ${validAlgorithms.join(', ')}`
      );
      process.exit(1);
    }

    consola.start(`Generating ${algorithm} key pair...`);

    const keyPair = await EmailVerificationIssuer.generateKeyPair(algorithm);
    const kid = args.kid || `evp-${Date.now()}`;

    // Add kid to the keys
    const privateKeyWithKid = { ...keyPair.privateKey, kid };
    const publicKeyWithKid = { ...keyPair.publicKey, kid };

    if (args.json) {
      console.log(
        formatJson({
          algorithm,
          kid,
          privateKey: privateKeyWithKid,
          publicKey: publicKeyWithKid,
        })
      );
      return;
    }

    console.log();
    console.log(formatSuccess('Key pair generated successfully'));
    console.log();
    console.log(
      formatTable([
        ['Algorithm', algorithm],
        ['Key ID', kid],
        ['Key Type', keyPair.publicKey.kty || 'unknown'],
      ])
    );

    console.log();
    console.log(formatHeader('Private Key (keep secret!)'));
    console.log(formatJson(privateKeyWithKid));

    console.log();
    console.log(formatHeader('Public Key (share via JWKS)'));
    console.log(formatJson(publicKeyWithKid));

    console.log();
    consola.info('Store the private key securely. Never commit it to version control.');
  },
});

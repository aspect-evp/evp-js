import * as fs from 'node:fs';
import { EVPError, type VerificationResult } from '@aspect-evp/core';
import { EmailVerificationVerifier } from '@aspect-evp/verifier';
import { defineCommand } from 'citty';
import consola from 'consola';
import { formatError, formatJson, formatSuccess, formatTable } from '../utils/format.js';

export const verifyCommand = defineCommand({
  meta: {
    name: 'verify',
    description: 'Verify an EVP SD-JWT+KB token',
  },
  args: {
    token: {
      type: 'string',
      alias: 't',
      description: 'SD-JWT+KB token to verify (or path to file)',
      required: true,
    },
    nonce: {
      type: 'string',
      alias: 'n',
      description: 'Expected nonce value',
      required: true,
    },
    origin: {
      type: 'string',
      alias: 'o',
      description: 'RP origin (audience)',
      required: true,
    },
    issuerUrl: {
      type: 'string',
      alias: 'i',
      description: 'Issuer base URL (for JWKS fetch)',
    },
    jwks: {
      type: 'string',
      description: 'Path to JWKS file (for offline verification)',
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    // Read token (from arg or file)
    let token = args.token;
    if (fs.existsSync(token)) {
      token = fs.readFileSync(token, 'utf-8').trim();
    }

    consola.start('Verifying token...');

    try {
      let result: VerificationResult;

      if (args.jwks) {
        // Offline verification with local JWKS
        const jwksContent = fs.readFileSync(args.jwks, 'utf-8');
        const jwks = JSON.parse(jwksContent);

        // Create mock fetch that returns the JWKS
        const mockFetch = async (url: string) => {
          if (url.includes('jwks') || url.includes('.well-known')) {
            return new Response(JSON.stringify(jwks), {
              headers: { 'Content-Type': 'application/json' },
            });
          }
          throw new Error(`Unexpected fetch: ${url}`);
        };

        // Create mock DNS resolver
        const mockDns = async () => args.issuerUrl || 'mock-issuer';

        const verifier = new EmailVerificationVerifier({
          rpOrigin: args.origin,
          dnsResolver: mockDns,
          fetch: mockFetch as typeof globalThis.fetch,
        });

        result = await verifier.verify(token, args.nonce);
      } else if (args.issuerUrl) {
        // Online verification
        const verifier = new EmailVerificationVerifier({
          rpOrigin: args.origin,
        });

        result = await verifier.verify(token, args.nonce);
      } else {
        consola.error('Either --issuerUrl or --jwks is required');
        process.exit(1);
      }

      if (args.json) {
        console.log(
          formatJson({
            valid: true,
            email: result.email,
            issuer: result.issuer,
            issuedAt: result.issuedAt.toISOString(),
          })
        );
        return;
      }

      console.log();
      console.log(formatSuccess('Token verified successfully'));
      console.log();
      console.log(
        formatTable([
          ['Email', result.email],
          ['Issuer', result.issuer],
          ['Issued At', result.issuedAt.toISOString()],
          ['Nonce', args.nonce],
          ['Audience', args.origin],
        ])
      );
    } catch (error) {
      if (args.json) {
        const errorInfo: { valid: boolean; error: string; code?: string } = {
          valid: false,
          error: error instanceof Error ? error.message : String(error),
        };
        if (error instanceof EVPError) {
          errorInfo.code = error.code;
        }
        console.log(formatJson(errorInfo));
        process.exit(1);
      }

      console.log();
      console.log(formatError('Token verification failed'));
      console.log();

      if (error instanceof EVPError) {
        console.log(
          formatTable([
            ['Error Code', error.code],
            ['Message', error.message],
          ])
        );
      } else {
        console.log(error instanceof Error ? error.message : String(error));
      }
      process.exit(1);
    }
  },
});

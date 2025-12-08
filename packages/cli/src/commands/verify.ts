import * as fs from 'node:fs';
import { EVPError, type VerificationResult } from '@aspect-evp/core';
import { EmailVerificationVerifier } from '@aspect-evp/verifier';
import { defineCommand } from 'citty';
import consola from 'consola';
import { formatError, formatJson, formatSuccess, formatTable } from '../utils/format.js';

/** Read token from file path or return as-is */
function readToken(tokenOrPath: string): string {
  if (fs.existsSync(tokenOrPath)) {
    return fs.readFileSync(tokenOrPath, 'utf-8').trim();
  }
  return tokenOrPath;
}

/** Create verifier for offline mode with local JWKS */
function createOfflineVerifier(jwksPath: string, origin: string, issuerUrl?: string) {
  const jwksContent = fs.readFileSync(jwksPath, 'utf-8');
  const jwks = JSON.parse(jwksContent);

  const mockFetch = async (url: string) => {
    if (url.includes('jwks') || url.includes('.well-known')) {
      return new Response(JSON.stringify(jwks), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };

  const mockDns = async () => issuerUrl || 'mock-issuer';

  return new EmailVerificationVerifier({
    rpOrigin: origin,
    dnsResolver: mockDns,
    fetch: mockFetch as typeof globalThis.fetch,
  });
}

/** Create verifier for online mode */
function createOnlineVerifier(origin: string) {
  return new EmailVerificationVerifier({ rpOrigin: origin });
}

/** Output successful verification result */
function outputSuccess(result: VerificationResult, nonce: string, origin: string, asJson: boolean) {
  if (asJson) {
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
      ['Nonce', nonce],
      ['Audience', origin],
    ])
  );
}

/** Output verification error */
function outputError(error: unknown, asJson: boolean): never {
  if (asJson) {
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
    const token = readToken(args.token);
    consola.start('Verifying token...');

    try {
      let verifier: EmailVerificationVerifier;

      if (args.jwks) {
        verifier = createOfflineVerifier(args.jwks, args.origin, args.issuerUrl);
      } else if (args.issuerUrl) {
        verifier = createOnlineVerifier(args.origin);
      } else {
        consola.error('Either --issuerUrl or --jwks is required');
        process.exit(1);
      }

      const result = await verifier.verify(token, args.nonce);
      outputSuccess(result, args.nonce, args.origin, args.json);
    } catch (error) {
      outputError(error, args.json);
    }
  },
});

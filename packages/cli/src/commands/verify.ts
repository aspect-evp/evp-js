import * as fs from 'node:fs';
import {
  decodeJWTPayload,
  EVPError,
  type IssuanceTokenPayload,
  parseSDJWTKB,
  type VerificationResult,
} from '@aspect-evp/core';
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
function issuerIdentifier(value: string): string {
  try {
    return new URL(value.includes('://') ? value : `https://${value}`).hostname;
  } catch {
    throw new EVPError('invalid_request', `Invalid issuer URL: ${value}`);
  }
}

function issuerFromToken(token: string): string {
  const { sdJwt } = parseSDJWTKB(token);
  const payload = sdJwt.slice(0, -1).split('.')[1];
  if (!payload) throw new EVPError('invalid_token', 'EVT payload is missing');
  const { iss } = decodeJWTPayload<IssuanceTokenPayload>(payload);
  if (typeof iss !== 'string') throw new EVPError('invalid_token', 'EVT issuer is missing');
  return iss;
}

function createOfflineVerifier(
  jwksPath: string,
  origin: string,
  token: string,
  issuerUrl?: string
) {
  const jwksContent = fs.readFileSync(jwksPath, 'utf-8');
  const jwks = JSON.parse(jwksContent);
  const issuer = issuerUrl ? issuerIdentifier(issuerUrl) : issuerFromToken(token);
  const jwksUri = `https://${issuer}/email-verification/jwks`;

  const mockFetch = async (url: string) => {
    if (url.includes('.well-known')) {
      return new Response(
        JSON.stringify({
          issuance_endpoint: `https://${issuer}/email-verification/issuance`,
          jwks_uri: jwksUri,
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );
    }
    if (url === jwksUri) {
      return new Response(JSON.stringify(jwks), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };

  const mockDns = async () => issuer;

  return new EmailVerificationVerifier({
    rpOrigin: origin,
    dnsResolver: mockDns,
    fetch: mockFetch as typeof globalThis.fetch,
  });
}

/** Create verifier for online mode */
function createOnlineVerifier(origin: string, issuerUrl?: string) {
  return new EmailVerificationVerifier({
    rpOrigin: origin,
    ...(issuerUrl ? { dnsResolver: async () => issuerIdentifier(issuerUrl) } : {}),
  });
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
    description: 'Verify an EVP EVT+KB token',
  },
  args: {
    token: {
      type: 'string',
      alias: 't',
      description: 'EVT+KB token to verify (or path to file)',
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
        verifier = createOfflineVerifier(args.jwks, args.origin, token, args.issuerUrl);
      } else {
        verifier = createOnlineVerifier(args.origin, args.issuerUrl);
      }

      const result = await verifier.verify(token, args.nonce);
      outputSuccess(result, args.nonce, args.origin, args.json);
    } catch (error) {
      outputError(error, args.json);
    }
  },
});

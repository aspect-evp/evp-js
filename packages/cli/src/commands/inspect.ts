import * as fs from 'node:fs';
import { base64urlDecode, parseSDJWTKB } from '@aspect-evp/core';
import { defineCommand } from 'citty';
import consola from 'consola';
import pc from 'picocolors';
import {
  formatDim,
  formatHeader,
  formatJson,
  formatSuccess,
  formatTable,
  formatWarning,
  symbols,
} from '../utils/format.js';

interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  [key: string]: unknown;
}

interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  nonce?: string;
  sd_hash?: string;
  cnf?: { jwk: JsonWebKey };
  [key: string]: unknown;
}

interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
}

/** Read token from file path or return as-is */
function readToken(tokenOrPath: string): string {
  if (fs.existsSync(tokenOrPath)) {
    return fs.readFileSync(tokenOrPath, 'utf-8').trim();
  }
  return tokenOrPath;
}

/** Decode a JWT into header and payload */
function decodeJWT(jwt: string): DecodedJWT {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const [headerPart, payloadPart] = parts as [string, string, string];
  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerPart))) as JWTHeader;
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadPart))) as JWTPayload;

  return { header, payload };
}

/** Format a Unix timestamp with expiry status */
function formatTimestamp(ts: number | undefined): string {
  if (!ts) return 'N/A';
  const date = new Date(ts * 1000);
  const diff = ts * 1000 - Date.now();

  let status = pc.green(' (valid)');
  if (diff < 0) {
    status = pc.red(' (expired)');
  } else if (diff < 60000) {
    status = pc.yellow(' (expiring soon)');
  }

  return `${date.toISOString()}${status}`;
}

/** Output as JSON format */
function outputJson(
  sdJwt: string,
  sdJwtDecoded: DecodedJWT,
  kbJwt: string | null,
  kbJwtDecoded: DecodedJWT | null
) {
  console.log(
    formatJson({
      sdJwt: {
        raw: sdJwt,
        header: sdJwtDecoded.header,
        payload: sdJwtDecoded.payload,
      },
      kbJwt: kbJwtDecoded
        ? {
            raw: kbJwt,
            header: kbJwtDecoded.header,
            payload: kbJwtDecoded.payload,
          }
        : null,
    })
  );
}

/** Print EVT section */
function printSDJwtSection(decoded: DecodedJWT) {
  console.log();
  console.log(formatHeader('EVT (Issuer Token)'));
  console.log(formatDim('─'.repeat(50)));

  console.log();
  console.log(`  ${pc.bold('Header:')}`);
  console.log(
    formatTable([
      ['Algorithm', decoded.header.alg],
      ['Type', decoded.header.typ || 'N/A'],
      ['Key ID', decoded.header.kid || 'N/A'],
    ])
  );

  console.log();
  console.log(`  ${pc.bold('Payload:')}`);
  console.log(
    formatTable([
      ['Issuer (iss)', decoded.payload.iss || 'N/A'],
      ['Subject (sub)', decoded.payload.sub || 'N/A'],
      ['Issued At (iat)', formatTimestamp(decoded.payload.iat)],
      ['Expires (exp)', formatTimestamp(decoded.payload.exp)],
    ])
  );

  if (decoded.payload.cnf?.jwk) {
    console.log();
    console.log(`  ${pc.bold('Confirmation Key (cnf):')}`);
    console.log(formatJson(decoded.payload.cnf.jwk));
  }
}

/** Print KB-JWT section */
function printKBJwtSection(decoded: DecodedJWT | null) {
  if (!decoded) {
    console.log();
    console.log(formatWarning('No KB-JWT found (token is EVT only, not EVT+KB)'));
    return;
  }

  console.log();
  console.log(formatHeader('KB-JWT (Key Binding Token)'));
  console.log(formatDim('─'.repeat(50)));

  console.log();
  console.log(`  ${pc.bold('Header:')}`);
  console.log(
    formatTable([
      ['Algorithm', decoded.header.alg],
      ['Type', decoded.header.typ || 'N/A'],
    ])
  );

  console.log();
  console.log(`  ${pc.bold('Payload:')}`);
  const payload = decoded.payload;
  console.log(
    formatTable([
      ['Audience (aud)', String(payload.aud) || 'N/A'],
      ['Nonce', payload.nonce || 'N/A'],
      ['Issued At (iat)', formatTimestamp(payload.iat)],
      ['SD Hash', payload.sd_hash ? `${payload.sd_hash.slice(0, 20)}...` : 'N/A'],
    ])
  );
}

/** Print summary section */
function printSummary(sdJwtDecoded: DecodedJWT, kbJwtDecoded: DecodedJWT | null) {
  console.log();
  console.log(formatHeader('Summary'));
  console.log(formatDim('─'.repeat(50)));
  console.log();

  const email = sdJwtDecoded.payload.sub;
  const issuer = sdJwtDecoded.payload.iss;
  const audience = kbJwtDecoded?.payload.aud;
  const nonce = kbJwtDecoded?.payload.nonce;

  console.log(`  ${symbols.bullet} Email: ${pc.cyan(email || 'N/A')}`);
  console.log(`  ${symbols.bullet} Issuer: ${pc.cyan(issuer || 'N/A')}`);
  if (audience) {
    console.log(`  ${symbols.bullet} Audience: ${pc.cyan(String(audience))}`);
  }
  if (nonce) {
    console.log(`  ${symbols.bullet} Nonce: ${pc.cyan(nonce)}`);
  }

  console.log();
  consola.info('This is a decode-only view. Use `evp verify` to validate signatures.');
}

export const inspectCommand = defineCommand({
  meta: {
    name: 'inspect',
    description: 'Inspect and decode an EVP token without verification',
  },
  args: {
    token: {
      type: 'positional',
      description: 'EVT+KB token to inspect (or path to file)',
      required: true,
    },
    json: {
      type: 'boolean',
      alias: 'j',
      description: 'Output as JSON',
      default: false,
    },
  },
  async run({ args }) {
    const token = readToken(args.token as string);

    try {
      const { sdJwt, kbJwt } = parseSDJWTKB(token);
      const sdJwtDecoded = decodeJWT(sdJwt);
      const kbJwtDecoded = kbJwt ? decodeJWT(kbJwt) : null;

      if (args.json) {
        outputJson(sdJwt, sdJwtDecoded, kbJwt, kbJwtDecoded);
        return;
      }

      console.log();
      console.log(formatSuccess('Token parsed successfully'));

      printSDJwtSection(sdJwtDecoded);
      printKBJwtSection(kbJwtDecoded);
      printSummary(sdJwtDecoded, kbJwtDecoded);
    } catch (error) {
      consola.error(
        'Failed to parse token:',
        error instanceof Error ? error.message : String(error)
      );
      process.exit(1);
    }
  },
});

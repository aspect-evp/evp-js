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

function decodeJWT(jwt: string): { header: JWTHeader; payload: JWTPayload } {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const headerPart = parts[0]!;
  const payloadPart = parts[1]!;

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(headerPart))) as JWTHeader;
  const payload = JSON.parse(new TextDecoder().decode(base64urlDecode(payloadPart))) as JWTPayload;

  return { header, payload };
}

function formatTimestamp(ts: number | undefined): string {
  if (!ts) return 'N/A';
  const date = new Date(ts * 1000);
  const now = Date.now();
  const diff = ts * 1000 - now;

  let status = '';
  if (diff < 0) {
    status = pc.red(' (expired)');
  } else if (diff < 60000) {
    status = pc.yellow(' (expiring soon)');
  } else {
    status = pc.green(' (valid)');
  }

  return `${date.toISOString()}${status}`;
}

export const inspectCommand = defineCommand({
  meta: {
    name: 'inspect',
    description: 'Inspect and decode an EVP token without verification',
  },
  args: {
    token: {
      type: 'positional',
      description: 'SD-JWT+KB token to inspect (or path to file)',
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
    // Read token (from arg or file)
    let token = args.token as string;
    if (fs.existsSync(token)) {
      token = fs.readFileSync(token, 'utf-8').trim();
    }

    try {
      const { sdJwt, kbJwt } = parseSDJWTKB(token);

      const sdJwtDecoded = decodeJWT(sdJwt);
      const kbJwtDecoded = kbJwt ? decodeJWT(kbJwt) : null;

      if (args.json) {
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
        return;
      }

      console.log();
      console.log(formatSuccess('Token parsed successfully'));

      // SD-JWT Section
      console.log();
      console.log(formatHeader('SD-JWT (Issuer Token)'));
      console.log(formatDim('─'.repeat(50)));

      console.log();
      console.log(`  ${pc.bold('Header:')}`);
      console.log(
        formatTable([
          ['Algorithm', sdJwtDecoded.header.alg],
          ['Type', sdJwtDecoded.header.typ || 'N/A'],
          ['Key ID', sdJwtDecoded.header.kid || 'N/A'],
        ])
      );

      console.log();
      console.log(`  ${pc.bold('Payload:')}`);
      const sdPayload = sdJwtDecoded.payload;
      console.log(
        formatTable([
          ['Issuer (iss)', sdPayload.iss || 'N/A'],
          ['Subject (sub)', sdPayload.sub || 'N/A'],
          ['Issued At (iat)', formatTimestamp(sdPayload.iat)],
          ['Expires (exp)', formatTimestamp(sdPayload.exp)],
        ])
      );

      if (sdPayload.cnf?.jwk) {
        console.log();
        console.log(`  ${pc.bold('Confirmation Key (cnf):')}`);
        console.log(formatJson(sdPayload.cnf.jwk));
      }

      // KB-JWT Section
      if (kbJwtDecoded) {
        console.log();
        console.log(formatHeader('KB-JWT (Key Binding Token)'));
        console.log(formatDim('─'.repeat(50)));

        console.log();
        console.log(`  ${pc.bold('Header:')}`);
        console.log(
          formatTable([
            ['Algorithm', kbJwtDecoded.header.alg],
            ['Type', kbJwtDecoded.header.typ || 'N/A'],
          ])
        );

        console.log();
        console.log(`  ${pc.bold('Payload:')}`);
        const kbPayload = kbJwtDecoded.payload;
        console.log(
          formatTable([
            ['Audience (aud)', String(kbPayload.aud) || 'N/A'],
            ['Nonce', kbPayload.nonce || 'N/A'],
            ['Issued At (iat)', formatTimestamp(kbPayload.iat)],
            ['SD Hash', kbPayload.sd_hash ? `${kbPayload.sd_hash.slice(0, 20)}...` : 'N/A'],
          ])
        );
      } else {
        console.log();
        console.log(formatWarning('No KB-JWT found (token is SD-JWT only, not SD-JWT+KB)'));
      }

      // Summary
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
    } catch (error) {
      consola.error(
        'Failed to parse token:',
        error instanceof Error ? error.message : String(error)
      );
      process.exit(1);
    }
  },
});

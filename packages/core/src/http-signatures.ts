import { importJWK, type JWK } from 'jose';
import { DEFAULT_CLOCK_TOLERANCE } from './constants.js';
import { EVPError } from './errors.js';
import { base64urlDecode, getCurrentTimestamp } from './utils.js';

const REQUIRED_COMPONENTS = ['@method', '@authority', '@path', 'signature-key'] as const;
const PRIVATE_JWK_FIELDS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'key_ops']);

export interface SignedIssuanceRequestOptions {
  cookie?: string;
  created?: number;
  headers?: Record<string, string>;
}

export interface VerifiedHttpMessageSignature {
  publicKey: JsonWebKey;
  algorithm: 'EdDSA' | 'ES256' | 'ES384' | 'RS256';
  created: number;
  coveredComponents: string[];
}

function quote(value: string): string {
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function publicJwk(privateJwk: JsonWebKey): JsonWebKey {
  return Object.fromEntries(
    Object.entries(privateJwk).filter(([key]) => !PRIVATE_JWK_FIELDS.has(key))
  ) as JsonWebKey;
}

function algorithmForJwk(jwk: JsonWebKey): 'EdDSA' | 'ES256' | 'ES384' | 'RS256' {
  if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') return 'EdDSA';
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') return 'ES256';
  if (jwk.kty === 'EC' && jwk.crv === 'P-384') return 'ES384';
  if (jwk.kty === 'RSA') return 'RS256';
  throw new EVPError('invalid_signature', 'Unsupported HTTP signature key');
}

function subtleAlgorithm(
  algorithm: 'EdDSA' | 'ES256' | 'ES384' | 'RS256'
): AlgorithmIdentifier | EcdsaParams {
  switch (algorithm) {
    case 'EdDSA':
      return 'Ed25519';
    case 'ES256':
      return { name: 'ECDSA', hash: 'SHA-256' };
    case 'ES384':
      return { name: 'ECDSA', hash: 'SHA-384' };
    case 'RS256':
      return 'RSASSA-PKCS1-v1_5';
  }
}

function serializeSignatureKey(label: string, jwk: JsonWebKey): string {
  const values: Array<[string, string | undefined]> = [
    ['kty', jwk.kty],
    ['crv', jwk.crv],
    ['x', jwk.x],
    ['y', jwk.y],
    ['n', jwk.n],
    ['e', jwk.e],
  ];
  const parameters = values
    .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    .map(([key, value]) => `${key}=${quote(value)}`);
  return `${label}=hwk; ${parameters.join('; ')}`;
}

function parseSignatureKey(value: string, expectedLabel: string): JsonWebKey {
  const match = value.match(/^([A-Za-z][A-Za-z0-9_-]*)=hwk(?:;\s*(.*))?$/);
  if (!match || match[1] !== expectedLabel || !match[2]) {
    throw new EVPError('invalid_signature', 'Malformed Signature-Key header');
  }

  const parameters: Record<string, string> & { kty?: string } = {};
  for (const part of match[2].split(/;\s*/)) {
    const parameter = part.match(/^([a-z][a-z0-9_]*)="((?:[^"\\]|\\.)*)"$/);
    if (!parameter?.[1] || parameter[2] === undefined) {
      throw new EVPError('invalid_signature', 'Malformed Signature-Key parameter');
    }
    parameters[parameter[1]] = parameter[2].replace(/\\([\\"])/g, '$1');
  }

  if (!parameters.kty) {
    throw new EVPError('invalid_signature', 'Signature-Key is missing kty');
  }
  const jwk: JsonWebKey = { kty: parameters.kty };
  for (const field of ['crv', 'x', 'y', 'n', 'e'] as const) {
    if (parameters[field]) jwk[field] = parameters[field];
  }
  algorithmForJwk(jwk);
  return jwk;
}

function parseSignatureInput(value: string): {
  label: string;
  components: string[];
  created: number;
  parameters: string;
} {
  const match = value.match(/^([A-Za-z][A-Za-z0-9_-]*)=(\((?:\s*"[^"]+"\s*)+\);created=([0-9]+))$/);
  if (!match?.[1] || !match[2] || !match[3]) {
    throw new EVPError('invalid_signature', 'Malformed Signature-Input header');
  }
  const components = [...match[2].matchAll(/"([^"]+)"/g)].map((item) => item[1]);
  return {
    label: match[1],
    components: components as string[],
    created: Number(match[3]),
    parameters: match[2],
  };
}

function parseSignature(value: string, label: string): Uint8Array {
  const match = value.match(new RegExp(`^${label}=:([A-Za-z0-9+/]+={0,2}):$`));
  if (!match?.[1]) throw new EVPError('invalid_signature', 'Malformed Signature header');
  try {
    const base64url = match[1].replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return base64urlDecode(base64url);
  } catch {
    throw new EVPError('invalid_signature', 'Malformed signature bytes');
  }
}

function componentValue(request: Request, component: string): string {
  const url = new URL(request.url);
  switch (component) {
    case '@method':
      return request.method.toUpperCase();
    case '@authority':
      return url.host;
    case '@path':
      return url.pathname;
    default: {
      const value = request.headers.get(component);
      if (value === null) {
        throw new EVPError('invalid_signature', `Covered component is missing: ${component}`);
      }
      return value;
    }
  }
}

function signatureBase(request: Request, components: string[], parameters: string): ArrayBuffer {
  const lines = components.map(
    (component) => `${quote(component.toLowerCase())}: ${componentValue(request, component)}`
  );
  lines.push(`"@signature-params": ${parameters}`);
  return new TextEncoder().encode(lines.join('\n')).buffer as ArrayBuffer;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function toBase64(bytes: ArrayBuffer): string {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Create the browser-side signed issuance request defined by the EVP draft. */
export async function createSignedIssuanceRequest(
  url: string,
  body: unknown,
  privateKey: JsonWebKey,
  options: SignedIssuanceRequestOptions = {}
): Promise<Request> {
  const label = 'sig';
  const publicKey = publicJwk(privateKey);
  const algorithm = algorithmForJwk(publicKey);
  const signatureKey = serializeSignatureKey(label, publicKey);
  const components = options.cookie
    ? ['@method', '@authority', '@path', 'cookie', 'signature-key']
    : [...REQUIRED_COMPONENTS];
  const created = options.created ?? getCurrentTimestamp();
  const parameters = `(${components.map(quote).join(' ')});created=${created}`;
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  headers.set('Sec-Fetch-Dest', 'email-verification');
  headers.set('Signature-Key', signatureKey);
  headers.set('Signature-Input', `${label}=${parameters}`);
  if (options.cookie) headers.set('Cookie', options.cookie);

  const unsignedRequest = new Request(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  const key = await importJWK(privateKey as JWK, algorithm);
  if (!(key instanceof CryptoKey)) {
    throw new EVPError('invalid_signature', 'HTTP signature key is not asymmetric');
  }
  const signature = await crypto.subtle.sign(
    subtleAlgorithm(algorithm),
    key,
    signatureBase(unsignedRequest, components, parameters)
  );
  headers.set('Signature', `${label}=:${toBase64(signature)}:`);
  return new Request(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

/** Verify the RFC 9421 signature profile used by EVP issuance requests. */
export async function verifyHttpMessageSignature(
  request: Request,
  clockTolerance = DEFAULT_CLOCK_TOLERANCE
): Promise<VerifiedHttpMessageSignature> {
  const signatureInputValue = request.headers.get('Signature-Input');
  const signatureValue = request.headers.get('Signature');
  const signatureKeyValue = request.headers.get('Signature-Key');
  if (!signatureInputValue || !signatureValue || !signatureKeyValue) {
    throw new EVPError('invalid_signature', 'Missing HTTP Message Signature headers');
  }

  const input = parseSignatureInput(signatureInputValue);
  for (const component of REQUIRED_COMPONENTS) {
    if (!input.components.includes(component)) {
      throw new EVPError('invalid_signature', `Signature does not cover ${component}`);
    }
  }
  const hasCookie = request.headers.has('Cookie');
  if (hasCookie !== input.components.includes('cookie')) {
    throw new EVPError('invalid_signature', 'Cookie coverage does not match the request');
  }
  if (Math.abs(getCurrentTimestamp() - input.created) > clockTolerance) {
    throw new EVPError('invalid_signature', 'HTTP signature timestamp is outside acceptable range');
  }

  const publicKey = parseSignatureKey(signatureKeyValue, input.label);
  const algorithm = algorithmForJwk(publicKey);
  const key = await importJWK(publicKey as JWK, algorithm);
  if (!(key instanceof CryptoKey)) {
    throw new EVPError('invalid_signature', 'HTTP signature key is not asymmetric');
  }
  const verified = await crypto.subtle.verify(
    subtleAlgorithm(algorithm),
    key,
    toArrayBuffer(parseSignature(signatureValue, input.label)),
    signatureBase(request, input.components, input.parameters)
  );
  if (!verified)
    throw new EVPError('invalid_signature', 'HTTP Message Signature verification failed');

  return {
    publicKey,
    algorithm,
    created: input.created,
    coveredComponents: input.components,
  };
}

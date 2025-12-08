# Implementation Plan

Este documento es una guía para implementar los paquetes EVP con Claude Code.

## Orden de Implementación

### Fase 1: @aspect-evp/core (Prioridad Alta)

Implementar primero ya que es dependencia de los otros paquetes.

#### 1.1 Archivos a crear

```
packages/core/src/
├── index.ts          # Re-exports públicos
├── types.ts          # Definiciones de tipos
├── errors.ts         # Clase EVPError
├── constants.ts      # Constantes del protocolo
├── utils.ts          # Funciones utilitarias
└── testing/
    ├── index.ts      # Re-exports de testing
    ├── test-flow.ts  # createTestFlow()
    └── mock-dns.ts   # MockDnsResolver
```

#### 1.2 Implementación de types.ts

```typescript
// Tipos principales a implementar:
// - IssuerMetadata
// - RequestTokenPayload
// - RequestTokenHeader  
// - IssuanceTokenPayload
// - IssuanceTokenHeader
// - KeyBindingPayload
// - VerificationResult
// - EVPErrorCode
```

#### 1.3 Implementación de errors.ts

```typescript
// EVPError class con:
// - code: EVPErrorCode
// - description?: string
// - Serialización JSON para HTTP responses
```

#### 1.4 Implementación de constants.ts

```typescript
// Constantes:
// - DEFAULT_ALGORITHM = 'EdDSA'
// - DEFAULT_CLOCK_TOLERANCE = 60
// - DNS_RECORD_PREFIX = '_email-verification'
// - WELL_KNOWN_PATH = '/.well-known/email-verification'
// - SD_JWT_TYPE = 'evp+sd-jwt'
// - KB_JWT_TYPE = 'kb+jwt'
```

#### 1.5 Implementación de utils.ts

```typescript
// Funciones:
// - parseSDJWTKB(token: string)
// - getEmailDomain(email: string)
// - isValidEmail(email: string)
// - sha256(data: string): Promise<string>
// - base64url(buffer: Uint8Array): string
// - base64urlDecode(str: string): Uint8Array
```

#### 1.6 Tests para core

```typescript
// tests/
// - types.test.ts (type guards)
// - errors.test.ts
// - utils.test.ts (cada función)
```

---

### Fase 2: @aspect-evp/issuer (Prioridad Alta)

Implementar después de core.

#### 2.1 Archivos a crear

```
packages/issuer/src/
├── index.ts          # Re-exports públicos
├── issuer.ts         # EmailVerificationIssuer class
├── middleware.ts     # createIssuerMiddleware()
└── keys.ts           # Utilidades de generación de llaves
```

#### 2.2 Implementación de issuer.ts

```typescript
// EmailVerificationIssuer class con:
// - constructor(config: IssuerConfig)
// - getMetadata(baseUrl: string): IssuerMetadata
// - getJWKS(): Promise<{ keys: JsonWebKey[] }>
// - verifyRequestToken(token: string): Promise<VerifyResult>
// - issueToken(email: string, browserPublicKey: JsonWebKey): Promise<string>
// - static generateKeyPair(algorithm?: string): Promise<KeyPair>
```

#### 2.3 Implementación de middleware.ts

```typescript
// createIssuerMiddleware() que:
// - Acepta issuer + función de verificación de usuario
// - Retorna objeto con handleIssuance(Request): Promise<Response>
// - Maneja todos los error codes del spec
```

#### 2.4 Tests para issuer

```typescript
// tests/
// - issuer.test.ts
//   - Generación de metadata
//   - Generación de JWKS
//   - Verificación de request tokens
//   - Emisión de tokens
// - middleware.test.ts
//   - Headers requeridos
//   - Error responses
```

---

### Fase 3: @aspect-evp/verifier (Prioridad Alta)

Implementar después de core.

#### 3.1 Archivos a crear

```
packages/verifier/src/
├── index.ts          # Re-exports públicos
├── verifier.ts       # EmailVerificationVerifier class
├── dns.ts            # DNS resolvers (DoH + Node.js)
└── jwks.ts           # JWKS fetching utilities
```

#### 3.2 Implementación de verifier.ts

```typescript
// EmailVerificationVerifier class con:
// - constructor(config: VerifierConfig)
// - verify(sdJwtKb: string, expectedNonce: string): Promise<VerificationResult>
// - private fetchIssuerMetadata(issuer: string): Promise<IssuerMetadata>
// - private verifyKeyBinding(...): Promise<void>
```

#### 3.3 Implementación de dns.ts

```typescript
// Funciones:
// - defaultDnsResolver(domain: string): Promise<string | null> // DoH
// - nodeDnsResolver(domain: string): Promise<string | null>    // Node.js native
```

#### 3.4 Tests para verifier

```typescript
// tests/
// - verifier.test.ts
//   - Verificación de tokens válidos
//   - Rechazo de nonce incorrecto
//   - Rechazo de audience incorrecto
//   - Rechazo de sd_hash incorrecto
//   - Rechazo de tokens expirados
// - dns.test.ts
//   - Mock DNS resolver
//   - DoH resolver (con mocks)
```

---

### Fase 4: Testing Utilities (Prioridad Media)

Completar utilidades de testing en @aspect-evp/core.

#### 4.1 Implementación de test-flow.ts

```typescript
// createTestFlow() que:
// - Genera keypairs de prueba
// - Crea issuer pre-configurado
// - Crea verifier pre-configurado
// - Simula el flujo del browser
```

#### 4.2 Implementación de mock-dns.ts

```typescript
// MockDnsResolver class:
// - addRecord(domain: string, issuer: string)
// - removeRecord(domain: string)
// - resolve(domain: string): Promise<string | null>
```

---

### Fase 5: Examples (Prioridad Baja)

Crear ejemplos funcionales.

```
examples/
├── express-issuer/
│   ├── package.json
│   ├── src/
│   │   └── server.ts
│   └── README.md
├── express-verifier/
│   ├── package.json
│   ├── src/
│   │   └── server.ts
│   └── README.md
└── full-flow/
    ├── package.json
    ├── src/
    │   └── demo.ts
    └── README.md
```

---

## Comandos para Claude Code

### Setup inicial

```bash
cd /path/to/evp
pnpm install
```

### Desarrollo

```bash
# Build todo
pnpm build

# Tests
pnpm test

# Tests con watch
pnpm test:watch

# Lint
pnpm lint

# Type check
pnpm typecheck
```

### Por paquete

```bash
# Build un paquete
cd packages/core
pnpm build

# Test un paquete
cd packages/issuer
pnpm test
```

---

## Checklist de Calidad

### Para cada función/clase

- [ ] JSDoc completo con ejemplos
- [ ] Tipos explícitos (no `any`)
- [ ] Tests unitarios
- [ ] Manejo de errores con EVPError
- [ ] Edge cases considerados

### Para cada paquete

- [ ] README.md actualizado
- [ ] Exports correctos en index.ts
- [ ] Types exportados
- [ ] Build sin errores
- [ ] Tests pasan
- [ ] Coverage >= 80%

### Antes de release

- [ ] Todos los tests pasan
- [ ] Lint sin errores
- [ ] Documentación completa
- [ ] CHANGELOG actualizado
- [ ] Versiones sincronizadas

---

## Notas Importantes

### Sobre jose

```typescript
// Imports específicos para tree-shaking:
import { SignJWT, jwtVerify, importJWK, exportJWK, generateKeyPair } from 'jose';
import { createRemoteJWKSet } from 'jose';
```

### Sobre crypto

```typescript
// Usar Web Crypto API (funciona en Node 18+, browsers, edge)
const hash = await crypto.subtle.digest('SHA-256', data);

// NO usar:
// - crypto.createHash() de Node.js (no portable)
// - librerías externas de crypto
```

### Sobre DNS

```typescript
// En browsers/edge: usar DoH (fetch a cloudflare-dns.com)
// En Node.js: ofrecer opción de usar dns/promises

// La opción DoH es el default porque funciona en todos lados
```

---

## Decisiones Pendientes

1. **¿Soportar algoritmos legacy como RS256?**
   - Pro: Compatibilidad con sistemas existentes
   - Con: RSA es más lento y keys más grandes
   - Decisión: Sí, pero EdDSA como default

2. **¿Incluir validación de email más robusta?**
   - Pro: Mejor UX, menos errores
   - Con: Scope creep, el issuer valida de todos modos
   - Decisión: Mantener básica, documentar limitaciones

3. **¿Cache de JWKS configurable?**
   - Pro: Más control
   - Con: jose ya maneja esto bien
   - Decisión: Delegar a jose por ahora

---

## Recursos

- [EVP Spec](https://github.com/WICG/email-verification-protocol)
- [SD-JWT RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)
- [jose Documentation](https://github.com/panva/jose)
- [Chrome Intent to Prototype](https://groups.google.com/a/chromium.org/g/blink-dev/c/pWfWupaOtJw)

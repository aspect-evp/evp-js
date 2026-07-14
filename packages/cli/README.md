# @aspect-evp/cli

> CLI tool for Email Verification Protocol (EVP) testing and development.

[![npm version](https://img.shields.io/npm/v/@aspect-evp/cli.svg)](https://www.npmjs.com/package/@aspect-evp/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
# Global installation
npm install -g @aspect-evp/cli

# Or use with npx
npx @aspect-evp/cli --help
```

## Commands

### `evp test` - Full Flow Simulation

Run a complete EVP flow simulation:

```bash
# Basic test
evp test

# Custom parameters
evp test --email user@gmail.com --issuer mail.google.com --origin https://myapp.com

# Verbose output
evp test -v

# JSON output
evp test -j
```

### `evp keygen` - Generate Key Pairs

Generate signing keys for an EVP issuer:

```bash
# Generate EdDSA key pair (recommended)
evp keygen

# Specify algorithm
evp keygen --algorithm ES256

# With custom key ID
evp keygen --kid 2024-01-signing-key

# JSON output (for piping)
evp keygen -j > keys.json
```

### `evp dns` - DNS Lookup

Check if a domain has EVP DNS records:

```bash
# Lookup EVP record
evp dns gmail.com

# Use Node.js DNS resolver
evp dns gmail.com --resolver node

# JSON output
evp dns gmail.com -j
```

### `evp inspect` - Token Inspection

Decode and inspect an EVP token without verification:

```bash
# Inspect a token
evp inspect "eyJhbGciOiJFZERTQSJ9..."

# From file
evp inspect ./token.txt

# JSON output
evp inspect ./token.txt -j
```

### `evp issue` - Issue Tokens

Issue an EVT for testing:

```bash
# Issue token
evp issue --email user@example.com --issuer mail.example.com --key ./private-key.json

# JSON output
evp issue -e user@example.com -i mail.example.com -k ./key.json -j
```

### `evp verify` - Verify Tokens

Verify an EVT+KB token:

```bash
# Verify with local JWKS
evp verify --token ./token.txt --nonce abc123 --origin https://myapp.com --jwks ./jwks.json

# Verify online (fetches JWKS from issuer)
evp verify -t ./token.txt -n abc123 -o https://myapp.com --issuerUrl https://mail.example.com
```

## Examples

### Complete Test Flow

```bash
# 1. Run the test simulation
evp test -v

# Output:
# ✓ Generate test keys
# ✓ Configure mock DNS
# ✓ Generate session nonce
# ✓ Issue EVT
# ✓ Create Key Binding JWT
# ✓ Verify EVT+KB token
#
# Verification Result:
#   Email: user@example.com
#   Issuer: issuer.example.com
#   Issued At: 2024-01-15T10:30:00.000Z
```

### Generate Keys for Production

```bash
# Generate and save keys
evp keygen -j > keys.json

# Extract public key for JWKS
cat keys.json | jq '.publicKey' > public-key.json
```

### Check Domain Support

```bash
# Check if Gmail supports EVP
evp dns gmail.com

# Check multiple domains
for domain in gmail.com outlook.com yahoo.com; do
  evp dns $domain -j
done
```

## Programmatic Usage

```typescript
import { testCommand } from '@aspect-evp/cli';

// Commands can be imported and used programmatically
// Useful for building custom tooling
```

## License

MIT

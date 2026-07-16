<!-- generated-by: gsd-doc-writer -->
# EVP documentation

This documentation is organized as a guided path: start with the protocol, choose the role you are implementing, and finish with the operational and contribution guides.

## Start here

1. [Getting started](GETTING-STARTED.md) — install the workspace and run a complete local verification.
2. [Protocol flow](PROTOCOL-FLOW.md) — understand DNS discovery, issuance, EVT, and key binding.
3. Choose your role:
   - [Issuer guide](issuer.md) for email providers.
   - [Verifier guide](verifier.md) for relying parties.
   - [Core API](core.md) for shared protocol primitives and test fixtures.

## Design and operations

| Guide | Use it when you need to… |
|---|---|
| [Architecture](ARCHITECTURE.md) | Understand package boundaries, trust boundaries, and data flow. |
| [Standards status](STANDARDS-CONFORMANCE.md) | Understand the conformance target, assurance boundaries, and unresolved upstream differences. |
| [Configuration](CONFIGURATION.md) | Configure issuer and verifier instances safely. |
| [Testing](TESTING.md) | Run, extend, and interpret the test and coverage suite. |
| [Development](DEVELOPMENT.md) | Build, lint, type-check, and prepare a pull request. |
| [CLI package](../packages/cli/README.md) | Generate keys, inspect tokens, or run local simulations. |

## Reference status

The implementation tracks `draft-hardt-email-verification-00`. The draft and the WICG browser API are experimental and may change. [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) is retained only as historical context; it is not an API reference.

## Package documentation

- [`@aspect-evp/core`](../packages/core/README.md)
- [`@aspect-evp/issuer`](../packages/issuer/README.md)
- [`@aspect-evp/verifier`](../packages/verifier/README.md)
- [`@aspect-evp/cli`](../packages/cli/README.md)

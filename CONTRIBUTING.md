# Contributing to EVP

Thank you for your interest in contributing to the Email Verification Protocol libraries!

## Getting Started

### Prerequisites

- Node.js 18+
- pnpm 8+

### Setup

```bash
# Clone the repository
git clone https://github.com/evp-js/evp.git
cd evp

# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test
```

## Development Workflow

### Project Structure

```
evp/
├── packages/
│   ├── core/       # Shared types, constants, utilities
│   ├── issuer/     # Issuer implementation
│   └── verifier/   # Verifier implementation
├── docs/           # Documentation
└── package.json    # Root workspace config
```

### Commands

```bash
# Build all packages
pnpm build

# Run all tests
pnpm test

# Run tests with coverage
pnpm test:coverage

# Type checking
pnpm typecheck

# Linting
pnpm lint
pnpm lint:fix
```

### Running Tests for a Specific Package

```bash
cd packages/core
pnpm test

cd packages/issuer
pnpm test

cd packages/verifier
pnpm test
```

## Making Changes

### Code Style

- Use TypeScript for all source code
- Follow existing code patterns
- Keep functions small and focused
- Add JSDoc comments for public APIs

### Testing

- Write tests for all new functionality
- Maintain >80% code coverage
- Use the testing utilities in `@evp/core/testing`

### Commit Messages

Use clear, descriptive commit messages:

```
feat(verifier): add custom DNS resolver support
fix(issuer): handle expired tokens correctly
docs: update API examples
test(core): add edge case tests for parseSDJWTKB
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run tests and ensure they pass
5. Push to your fork
6. Open a Pull Request

### PR Checklist

- [ ] Tests pass (`pnpm test`)
- [ ] Types check (`pnpm typecheck`)
- [ ] Lint passes (`pnpm lint`)
- [ ] Documentation updated if needed
- [ ] Commit messages are clear

## Areas Where Help is Needed

- Security review and threat modeling
- Test coverage for edge cases
- Documentation improvements
- Integration examples (Express, Hono, Fastify)
- API ergonomics feedback

## Questions?

Open an issue on GitHub for any questions or discussions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

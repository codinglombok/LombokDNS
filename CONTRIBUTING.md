# Contributing to LombokDNS

Thank you for considering a contribution to LombokDNS.

## Prerequisites

- **Node.js** ≥ 18 (recommended: 22 or 24)
- **npm** (comes with Node)
- **TypeScript** (installed via `npm ci`)

## Setup

```bash
git clone https://github.com/codinglombok/LombokDNS.git
cd LombokDNS
npm ci
```

## Development workflow

```bash
# Type-check (no output)
npx tsc --noEmit

# Build to dist/
npm run build

# Run tests
npm run test:full

# Verify pack content
npm pack --dry-run
```

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `fix:` — bug fix (triggers a PATCH release)
- `feat:` — new feature (triggers a MINOR release)
- `docs:` — documentation only (NO release)
- `ci:` — CI/workflow changes (NO release)
- `test:` — test additions (NO release)
- `chore:` — maintenance (NO release)

**Important:** `fix:` and `feat:` trigger releases regardless of scope.
A commit like `fix(docs):` WILL trigger a release even though it only
touches documentation — use `docs:` instead if no dist files changed.

## Adding a new record type

1. Add the enum value to `src/core/types.ts` (RRType)
2. Add the decode case to `src/core/rdata.ts` (decodeRData)
3. Add the encode case to `src/core/rdata.ts` (encodeRData)
4. Add zone file parse support to `src/zone/zonefile.ts` (TYPE_NAMES + parseRDataTokens)
5. Add format support to `src/utils/format.ts` (RRTypeInfo + formatRData)
6. Add tests to `tests/core.test.ts`
7. Add the RFC number to `docs/ARCHITECTURE.md`

## Testing requirements

- All tests must be assertion-based (not print-only)
- Every new feature needs a round-trip test (encode → decode → compare)
- Run the full suite before pushing: `npm run test:full`

## Code style

- Zero dependencies in `src/` — only Node built-ins and Uint8Array
- No `Buffer` usage (browser compatibility)
- ESM only (`"type": "module"`)
- TypeScript strict mode

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license.

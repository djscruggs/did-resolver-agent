# did-resolver-agent

## Project Purpose

A chain-agnostic MCP server + demo agent for agent authorization via W3C Verifiable Credentials and Decentralized Identifiers. Enables AI agents to prove delegated authority from a human without a central authority.

## Architecture

Two npm workspace packages:
- `mcp-server/` — MCP server exposing DID/VC tools
- `demo-agent/` — Claude-powered CLI demo of age-gated access control


## Stack

- TypeScript / Node
- `@modelcontextprotocol/sdk` — MCP server
- Universal Resolver (`https://dev.uniresolver.io`) — chain-agnostic DID resolution
- `@anthropic-ai/sdk` — demo agent
- Ed25519 keys, JWT-format VCs

## MCP Tools

| Tool | Purpose |
|------|---------|
| `resolve_did` | Fetch DID Document via Universal Resolver |
| `verify_credential` | Validate VC signature against issuer DID |
| `issue_credential` | Create a signed VC (Ed25519/JWT) |
| `check_delegation` | Compose above to authorize an agent action |

## Demo Scenario

1. Human DID issues a VC to an agent: `{ age_verified: true, over_21: true }`
2. Agent presents VC to a simulated resource server
3. MCP server resolves issuer DID, verifies signature, checks claims
4. Access granted or denied with reason

Test cases:
- Valid VC → granted
- Tampered VC → denied
- Expired VC → denied with reason

## Development Guidelines

- Follow Red/Green TDD for all business logic (crypto, VC parsing, claims checking)
- TypeScript strict mode on
- No secrets committed — use `.env` for any private keys in dev, gitignored
- Run `npm run typecheck` before marking any task done

## Code Architecture

### Separate Pure Logic (`src/lib/`) from IO (`src/tools/`)

Pure, side-effect-free business logic lives in `src/lib/` (e.g., `crypto.ts`, `vc.ts`). IO-dependent code (network calls, DID resolution) lives in `src/tools/` or `src/lib/resolver.ts`. Each `src/lib/` file must include a file-level JSDoc comment stating `No IO — testable in isolation`. Tool functions in `src/tools/` compose pure lib functions with IO as thin orchestration layers.

### Tool Function Naming

Name MCP tool handler functions in `src/tools/` with a `Tool` suffix (e.g., `resolveDIDTool`, `verifyCredentialTool`, `issueCredentialTool`). The underlying pure logic functions in `src/lib/` use plain names (e.g., `resolveDID`, `verifyCredentialJwt`, `issueCredential`). Tool functions accept a single input object and delegate to lib functions.

### Return Structured Result Objects for Domain Errors

Return typed result objects with explicit success/failure fields (`valid`/`authorized` booleans, `reason` strings) instead of throwing exceptions for expected failure cases. Catch exceptions only at crypto/encoding boundaries and convert them to result objects.

```ts
// Good
return { valid: false, reason: "Malformed JWT" };

// Bad — throwing for an expected domain error
throw new Error("Malformed JWT");
```

### Define Named Interface Types for Every Function Input and Output

Declare a named TypeScript interface for every tool and library function's input parameters and return type. Use descriptive names like `CheckDelegationInput`, `IssueInput`, `DelegationResult`, `VerifyResult`.

```ts
// Good
export interface CheckDelegationInput {
  agentDid: string;
  requestedAction: string;
  vcJwt: string;
  requiredClaims?: Record<string, unknown>;
}
export async function checkDelegation(input: CheckDelegationInput): Promise<DelegationResult> { ... }

// Bad — positional args + inline return type
export async function checkDelegation(
  agentDid: string, requestedAction: string, vcJwt: string
): Promise<{ authorized: boolean; reason: string }> { ... }
```

### Numbered Inline Comments for Multi-Step Validation

Prefix each step in a multi-step validation pipeline with a numbered comment (`// 1.`, `// 2.`, etc.). Each step returns early with a specific failure reason if validation fails.

```ts
// 1. Parse the VC
const payload = parseCredential(vcJwt);
if (!payload) return { authorized: false, reason: "Malformed VC JWT" };

// 2. Check the VC is addressed to this agent
if (payload.sub !== agentDid) {
  return { authorized: false, reason: `VC subject does not match` };
}

// 3. Resolve the issuer DID
...
```

## ESM Conventions

### Use `.js` Extensions in All TypeScript Import Paths

All relative import paths must use the `.js` extension, even though source files are `.ts`. This is required for NodeNext module resolution.

```ts
// Good
import { generateKeyPair } from "../lib/crypto.js";

// Bad
import { generateKeyPair } from "../lib/crypto";
```

## Testing Conventions

### ESM Module Mocking

Use `jest.unstable_mockModule()` before any dynamic import of the module under test. Import modules under test with top-level `await` (`const { fn } = await import(...)`). Never use `jest.mock()` — it does not work in ESM.

```ts
// Good
const mockResolveDID = jest.fn<() => Promise<ResolutionResult>>();
jest.unstable_mockModule("../lib/resolver.js", () => ({
  resolveDID: mockResolveDID,
}));
const { checkDelegation } = await import("../tools/delegate.js");

// Bad — jest.mock does not work in ESM
jest.mock("../lib/resolver.js");
import { checkDelegation } from "../tools/delegate.js";
```

### Test Structure

Use one `describe()` block per logical unit. Include both happy-path and adversarial tests (tampered data, expired tokens, wrong DIDs, malformed input, missing keys, resolution failures). Adversarial tests should outnumber happy-path tests. Name tests with lowercase descriptive phrases starting with a verb: `authorizes`, `denies`, `rejects`, `returns null`.

### Shared Test Fixture Factories

Define small async helper functions (e.g., `makeVC`, `mockResolver`) that accept optional overrides with sensible defaults. Regenerate keypairs in `beforeEach` for test isolation. Call `jest.clearAllMocks()` in `beforeEach`.

### Regex Matchers for Error Reason Assertions

Use `toMatch()` with regex patterns for error/reason string assertions instead of exact string comparisons. This makes tests resilient to minor wording changes.

```ts
// Good
expect(result.reason).toMatch(/expired/i);

// Bad
expect(result.reason).toBe("Credential expired at 2026-03-16T19:34:57.000Z");
```

### Integration Tests Behind Environment Variable

Guard integration tests requiring network access behind `INTEGRATION=true`. Use the conditional describe pattern at the top of the file and set an extended timeout on each test.

```ts
const SKIP = process.env.INTEGRATION !== "true";
const maybeDescribe = SKIP ? describe.skip : describe;

maybeDescribe("Universal Resolver (integration)", () => {
  it("resolves did:web:danubetech.com", async () => { ... }, 15000);
});
```

## Key References

- [W3C DID Core Spec](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Universal Resolver](https://dev.uniresolver.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [Anthropic Claude API](https://docs.anthropic.com)

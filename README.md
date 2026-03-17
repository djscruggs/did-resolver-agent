# did-resolver-agent

A chain-agnostic MCP server + demo agent for agent authorization via W3C Verifiable Credentials and Decentralized Identifiers.

Enables AI agents to prove delegated authority from a human without a central authority.

See [USE_CASES.md](./USE_CASES.md) for real-world scenarios.

## Architecture

```
Human
  │ issues VC (signed with human's DID key)
  ▼
Agent (Claude with tool use)
  │ calls MCP tools
  ▼
MCP Server
  ├── resolve_did        → DID Document (Universal Resolver)
  ├── verify_credential  → {valid, issuer, subject, claims, expiry}
  ├── issue_credential   → signed VC (JWT, Ed25519)
  └── check_delegation   → {authorized, reason}
```

Two npm workspace packages:
- `mcp-server/` — MCP server exposing DID/VC tools
- `demo-agent/` — Claude-powered CLI demo of age-gated access control

## Stack

- TypeScript / Node
- `@modelcontextprotocol/sdk` — MCP server
- `@noble/ed25519` + `@noble/hashes` — Ed25519 signing
- Universal Resolver (`https://dev.uniresolver.io`) — chain-agnostic DID resolution
- `@anthropic-ai/sdk` — demo agent

## Quick Start

```bash
npm install

# Run tests
npm test

# Type check
npm run typecheck

# Start MCP server
npm run dev --workspace=mcp-server

# Run demo agent (valid VC scenario)
npm run start --workspace=demo-agent -- valid

# Run demo agent (tampered VC)
npm run start --workspace=demo-agent -- tampered

# Run demo agent (expired VC)
npm run start --workspace=demo-agent -- expired
```

## MCP Tools

| Tool | Input | Output |
|------|-------|--------|
| `resolve_did` | `did: string` | DID Document JSON |
| `verify_credential` | `vcJwt: string` | `{valid, issuer, subject, claims, expires}` |
| `issue_credential` | `subjectDid, claims, issuerDid, privateKeyBase64url` | `{jwt}` |
| `check_delegation` | `agentDid, requestedAction, vcJwt, requiredClaims?` | `{authorized, reason}` |

## Demo Scenario

1. Human DID issues a VC to an agent: `{ age_verified: true, over_21: true }`
2. Agent presents VC to a simulated resource server
3. MCP server resolves issuer DID, verifies signature, checks claims
4. Access granted or denied with reason

Test cases:
- `valid` — Valid VC → granted
- `tampered` — Tampered VC payload → denied (signature mismatch)
- `expired` — Expired VC → denied with reason

## Project Structure

```
did-resolver-agent/
├── mcp-server/
│   ├── src/
│   │   ├── index.ts          # MCP server entry point
│   │   ├── tools/
│   │   │   ├── resolve.ts    # resolve_did tool
│   │   │   ├── verify.ts     # verify_credential tool
│   │   │   ├── issue.ts      # issue_credential tool
│   │   │   └── delegate.ts   # check_delegation tool
│   │   └── lib/
│   │       ├── crypto.ts     # Ed25519 key generation, signing, verification (pure)
│   │       ├── vc.ts         # JWT VC issue, parse, verify (pure)
│   │       └── resolver.ts   # Universal Resolver HTTP client
│   └── package.json
├── demo-agent/
│   ├── src/
│   │   ├── index.ts          # CLI entry point (valid/tampered/expired scenarios)
│   │   └── agent.ts          # Claude agent with MCP tool use
│   └── package.json
└── package.json              # npm workspace root
```

## Why This Matters

Agentic systems need a way to prove they are authorized to act on behalf of a human — without calling a central authority. DIDs + VCs provide the cryptographic primitives: a human can issue a signed, scoped credential to an agent, and any verifier can check it using only the DID document (no central registry).

> Built a chain-agnostic MCP server enabling agents to issue, verify, and act on W3C Verifiable Credentials anchored to decentralized identifiers. Implemented a delegated authorization model allowing humans to grant scoped permissions to AI agents via cryptographically signed credentials, verified without a central authority.

## References

- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Universal Resolver](https://dev.uniresolver.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)

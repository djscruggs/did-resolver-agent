# did-resolver-agent

## Project Purpose

A chain-agnostic MCP server + demo agent for agent authorization via W3C Verifiable Credentials and Decentralized Identifiers. Enables AI agents to prove delegated authority from a human without a central authority.

## Architecture

Two npm workspace packages:
- `mcp-server/` — MCP server exposing DID/VC tools
- `demo-agent/` — Claude-powered CLI demo of age-gated access control

See full plan: `plan.md`

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
- Keep pure logic (crypto, VC validation) separate from IO (HTTP calls, MCP transport)
- TypeScript strict mode on
- No secrets committed — use `.env` for any private keys in dev, gitignored
- Run `npx tsc --noEmit` before marking any task done

## Key References

- [W3C DID Core Spec](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Universal Resolver](https://dev.uniresolver.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
- [Anthropic Claude API](https://docs.anthropic.com)

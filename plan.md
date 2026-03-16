# Agent Authorization via Verifiable Credentials (MCP Server + Demo)

## Context

Agentic systems need a way to prove they are authorized to act on behalf of a human — without calling a central authority. Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs) provide the cryptographic primitives for this. This project builds:

1. An MCP server that exposes DID/VC operations as tools agents can call
2. A demo agent that uses the MCP server to enforce credential-based access control

This demonstrates "architecting advanced agentic systems" on a resume — specifically the unsolved problem of agent identity and delegated authorization.

---

## Stack

- **Language**: TypeScript / Node
- **MCP SDK**: `@modelcontextprotocol/sdk`
- **DID Resolution**: Universal Resolver (https://dev.uniresolver.io) — chain-agnostic, supports 100+ DID methods
- **VC handling**: `@digitalcredentials/vc` or `@veramo/core`
- **Demo agent**: Claude API (`@anthropic-ai/sdk`) with tool use

---

## Architecture

```
Human
  │
  │ issues VC to agent (JSON-LD, signed with human's DID key)
  ▼
Agent (Claude with tool use)
  │
  │ calls MCP tools
  ▼
MCP Server
  ├── resolve_did(did) → DID Document (via Universal Resolver)
  ├── verify_credential(vc) → {valid, issuer, subject, claims, expiry}
  ├── issue_credential(subject_did, claims, issuer_key) → signed VC
  └── check_delegation(agent_did, action, vc) → authorized/denied
  │
  ▼
Universal Resolver API (external)
```

---

## MCP Tools to Expose

| Tool | Input | Output |
|------|-------|--------|
| `resolve_did` | `did: string` | DID Document JSON |
| `verify_credential` | `vc: object` | `{valid, issuer, subject, claims, expires}` |
| `issue_credential` | `subject_did, claims, issuer_did, private_key` | signed VC (JWT or JSON-LD) |
| `check_delegation` | `agent_did, requested_action, vc` | `{authorized: bool, reason: string}` |

---

## Demo Agent Scenario

**"Age-gated content access"** (ties to Cardless ID):

1. Human has a DID and issues a VC to an agent: `{ age_verified: true, over_21: true }`
2. Agent tries to access a resource via the demo CLI
3. Resource server (simulated) calls `check_delegation` via MCP
4. MCP server resolves the issuer DID, verifies the VC signature, checks claims
5. Access granted or denied with explanation

This is a self-contained, runnable demo that tells a complete story.

---

## Project Structure

```
did-agent-auth/
├── mcp-server/
│   ├── src/
│   │   ├── index.ts          # MCP server entry point
│   │   ├── tools/
│   │   │   ├── resolve.ts    # resolve_did tool
│   │   │   ├── verify.ts     # verify_credential tool
│   │   │   ├── issue.ts      # issue_credential tool
│   │   │   └── delegate.ts   # check_delegation tool
│   │   └── lib/
│   │       ├── resolver.ts   # Universal Resolver client
│   │       └── crypto.ts     # key generation, signing, verification
│   └── package.json
├── demo-agent/
│   ├── src/
│   │   ├── index.ts          # CLI demo entry point
│   │   ├── agent.ts          # Claude agent with MCP tool use
│   │   └── fixtures/
│   │       ├── human.key.json    # sample issuer keypair
│   │       └── credential.json   # sample VC
│   └── package.json
├── README.md
└── package.json (workspace root)
```

---

## Implementation Steps

1. **Scaffold** — npm workspace with two packages: `mcp-server`, `demo-agent`
2. **MCP server core** — set up `@modelcontextprotocol/sdk` stdio server
3. **`resolve_did` tool** — HTTP call to Universal Resolver, return DID Document
4. **`verify_credential` tool** — parse VC, resolve issuer DID, verify signature
5. **`issue_credential` tool** — generate signed VC (JWT format, Ed25519)
6. **`check_delegation` tool** — compose resolve + verify + claims check
7. **Demo agent** — Claude API agent that uses MCP tools to enforce access control
8. **Fixtures** — pre-generated DID keypair + sample VC so demo runs offline-ish
9. **README** — architecture diagram, quickstart, explanation of why this matters

---

## Verification

- Run MCP server, call `resolve_did` with a known public DID (e.g. `did:web:danubetech.com`)
- Issue a test VC, then verify it — confirm valid/invalid round-trip
- Run demo agent: present valid VC → access granted; tamper with VC → access denied
- Run demo agent: present expired VC → denied with reason

---

## Resume Narrative

> "Built a chain-agnostic MCP server enabling agents to issue, verify, and act on W3C Verifiable Credentials anchored to decentralized identifiers. Implemented a delegated authorization model allowing humans to grant scoped permissions to AI agents via cryptographically signed credentials, verified without a central authority."

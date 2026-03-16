import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { resolveDIDTool } from "./tools/resolve.js";
import { verifyCredentialTool } from "./tools/verify.js";
import { issueCredentialTool } from "./tools/issue.js";
import { checkDelegation } from "./tools/delegate.js";

process.on("unhandledRejection", (reason: unknown) => {
  console.error("Unhandled Rejection:", reason);
  process.exit(1);
});

const server = new McpServer({ name: "did-resolver-agent", version: "0.1.0" });

server.registerTool(
  "resolve_did",
  {
    description: "Fetch a DID Document via the Universal Resolver",
    inputSchema: { did: z.string().describe("The DID to resolve, e.g. did:web:example.com") },
  },
  async ({ did }) => {
    const result = await resolveDIDTool(did);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.registerTool(
  "verify_credential",
  {
    description: "Verify a JWT-format Verifiable Credential against the issuer DID",
    inputSchema: { vcJwt: z.string().describe("The JWT-encoded VC") },
  },
  async ({ vcJwt }) => {
    const result = await verifyCredentialTool(vcJwt);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.registerTool(
  "issue_credential",
  {
    description: "Issue a signed JWT Verifiable Credential (Ed25519)",
    inputSchema: {
      subjectDid: z.string(),
      claims: z.record(z.string(), z.unknown()).describe("Claims to embed in the VC"),
      issuerDid: z.string(),
      privateKeyBase64url: z.string().describe("Base64url Ed25519 private key (32 bytes)"),
      expiresInSeconds: z.number().optional().describe("Optional TTL in seconds"),
    },
  },
  async (input) => {
    const result = await issueCredentialTool(input);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

server.registerTool(
  "check_delegation",
  {
    description: "Verify that an agent's VC authorizes a specific action",
    inputSchema: {
      agentDid: z.string(),
      requestedAction: z.string(),
      vcJwt: z.string(),
      requiredClaims: z.record(z.string(), z.unknown()).optional().describe("Key/value pairs that must be present in the VC claims"),
    },
  },
  async (input) => {
    const result = await checkDelegation(input);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);

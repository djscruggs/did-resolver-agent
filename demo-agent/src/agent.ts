/**
 * Claude-powered demo agent.
 * Uses MCP tools (via in-process call) to enforce credential-based access.
 */
import Anthropic from "@anthropic-ai/sdk";
import { resolveDIDTool } from "../../mcp-server/src/tools/resolve.js";
import { verifyCredentialTool } from "../../mcp-server/src/tools/verify.js";
import { issueCredentialTool } from "../../mcp-server/src/tools/issue.js";
import { checkDelegation } from "../../mcp-server/src/tools/delegate.js";
import { createChallengeTool, verifyAuthTool } from "../../mcp-server/src/tools/auth.js";
import { verifyDelegationChainTool } from "../../mcp-server/src/tools/verifyChain.js";

process.on("unhandledRejection", (reason: unknown) => {
  console.error("Unhandled Rejection:", reason);
  process.exit(1);
});

const client = new Anthropic();

const TOOLS: Anthropic.Tool[] = [
  {
    name: "resolve_did",
    description: "Fetch a DID Document via the Universal Resolver",
    input_schema: {
      type: "object" as const,
      properties: {
        did: { type: "string", description: "The DID to resolve" },
      },
      required: ["did"],
    },
  },
  {
    name: "verify_credential",
    description: "Verify a JWT-format Verifiable Credential against the issuer DID",
    input_schema: {
      type: "object" as const,
      properties: {
        vcJwt: { type: "string", description: "The JWT-encoded VC" },
      },
      required: ["vcJwt"],
    },
  },
  {
    name: "issue_credential",
    description: "Issue a signed JWT Verifiable Credential (Ed25519)",
    input_schema: {
      type: "object" as const,
      properties: {
        subjectDid: { type: "string" },
        claims: { type: "object" },
        issuerDid: { type: "string" },
        privateKeyBase64url: { type: "string" },
        expiresInSeconds: { type: "number" },
        audience: { type: "string" },
        delegatedFrom: { type: "string" },
      },
      required: ["subjectDid", "claims", "issuerDid", "privateKeyBase64url"],
    },
  },
  {
    name: "check_delegation",
    description: "Verify that an agent's VC authorizes a specific action",
    input_schema: {
      type: "object" as const,
      properties: {
        agentDid: { type: "string" },
        requestedAction: { type: "string" },
        vcJwt: { type: "string" },
        requiredClaims: { type: "object" },
        expectedAudience: { type: "string" },
        authProof: {
          type: "object",
          properties: {
            nonce: { type: "string" },
            issuedAt: { type: "number" },
            expiresAt: { type: "number" },
            signatureBase64url: { type: "string" },
          },
        },
      },
      required: ["agentDid", "requestedAction", "vcJwt"],
    },
  },
  {
    name: "create_challenge",
    description: "Generate an authentication challenge for an agent to sign",
    input_schema: {
      type: "object" as const,
      properties: {
        agentDid: { type: "string" },
        ttlSeconds: { type: "number" },
      },
      required: ["agentDid"],
    },
  },
  {
    name: "verify_auth",
    description: "Verify an agent's signed challenge response",
    input_schema: {
      type: "object" as const,
      properties: {
        agentDid: { type: "string" },
        nonce: { type: "string" },
        issuedAt: { type: "number" },
        signatureBase64url: { type: "string" },
        expiresAt: { type: "number" },
      },
      required: ["agentDid", "nonce", "issuedAt", "signatureBase64url"],
    },
  },
  {
    name: "verify_delegation_chain",
    description: "Verify a chain of delegation VCs from a root issuer down to an agent",
    input_schema: {
      type: "object" as const,
      properties: {
        vcChain: { type: "array", items: { type: "string" } },
        agentDid: { type: "string" },
      },
      required: ["vcChain", "agentDid"],
    },
  },
];

async function callTool(name: string, input: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case "resolve_did":
      return resolveDIDTool(input.did as string);
    case "verify_credential":
      return verifyCredentialTool(input.vcJwt as string);
    case "issue_credential":
      return issueCredentialTool(input as unknown as Parameters<typeof issueCredentialTool>[0]);
    case "check_delegation":
      return checkDelegation(input as unknown as Parameters<typeof checkDelegation>[0]);
    case "create_challenge":
      return createChallengeTool(input as Parameters<typeof createChallengeTool>[0]);
    case "verify_auth":
      return verifyAuthTool(input as unknown as Parameters<typeof verifyAuthTool>[0]);
    case "verify_delegation_chain":
      return verifyDelegationChainTool(input as Parameters<typeof verifyDelegationChainTool>[0]);
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

export async function runAgent(userPrompt: string): Promise<void> {
  console.log("\n─── Agent starting ───");
  console.log("User:", userPrompt);

  const messages: Anthropic.MessageParam[] = [{ role: "user", content: userPrompt }];

  while (true) {
    const response = await client.messages.create({
      model: "claude-sonnet-4-6",
      max_tokens: 4096,
      tools: TOOLS,
      messages,
    });

    // Add assistant response to history
    messages.push({ role: "assistant", content: response.content });

    if (response.stop_reason === "end_turn") {
      // Extract final text
      for (const block of response.content) {
        if (block.type === "text") {
          console.log("\nAgent:", block.text);
        }
      }
      break;
    }

    if (response.stop_reason === "tool_use") {
      const toolResults: Anthropic.ToolResultBlockParam[] = [];

      for (const block of response.content) {
        if (block.type === "tool_use") {
          console.log(`\n  → Calling tool: ${block.name}`);
          const result = await callTool(
            block.name,
            block.input as Record<string, unknown>
          );
          const resultText = JSON.stringify(result, null, 2);
          console.log(`  ← Result: ${resultText.slice(0, 200)}${resultText.length > 200 ? "..." : ""}`);

          toolResults.push({
            type: "tool_result",
            tool_use_id: block.id,
            content: resultText,
          });
        }
      }

      messages.push({ role: "user", content: toolResults });
    }
  }

  console.log("─── Agent done ───\n");
}

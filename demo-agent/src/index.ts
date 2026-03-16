/**
 * CLI demo: age-gated access control via Verifiable Credentials.
 *
 * Scenarios:
 *   node src/index.ts valid     → present valid VC, access granted
 *   node src/index.ts tampered  → tampered VC, access denied
 *   node src/index.ts expired   → expired VC, access denied with reason
 *
 * Key generation is done in-process at startup (no external DID required
 * for local testing). The "human" DID key pair is generated fresh, a VC
 * is issued to the "agent" DID, and the agent tries to access a resource.
 */
import { generateKeyPair, toBase64url } from "../../mcp-server/src/lib/crypto.js";
import { issueCredential } from "../../mcp-server/src/lib/vc.js";
import { runAgent } from "./agent.js";

process.on("unhandledRejection", (reason: unknown) => {
  console.error("Unhandled Rejection:", reason);
  process.exit(1);
});

async function main() {
  const scenario = process.argv[2] ?? "valid";

  // Generate a fresh human keypair for this demo run
  const humanKeyPair = await generateKeyPair();
  const humanPublicKeyB64 = toBase64url(humanKeyPair.publicKey);

  // Use did:key DIDs (simplified — real did:key encodes public key in the DID itself)
  // For local demo we use placeholder DIDs; in a real flow you'd register these
  const humanDid = `did:key:z_HUMAN_${humanPublicKeyB64.slice(0, 8)}`;
  const agentDid = `did:key:z_AGENT_demo`;

  // Issue a VC from human to agent
  let vcJwt: string;

  if (scenario === "expired") {
    const vc = await issueCredential(
      agentDid,
      { age_verified: true, over_21: true },
      humanDid,
      humanKeyPair,
      -1 // already expired
    );
    vcJwt = vc.jwt;
  } else {
    const vc = await issueCredential(
      agentDid,
      { age_verified: true, over_21: true },
      humanDid,
      humanKeyPair,
      3600 // 1 hour
    );
    vcJwt = vc.jwt;

    if (scenario === "tampered") {
      // Tamper with the payload section
      const parts = vcJwt.split(".");
      const fakePayload = Buffer.from(
        JSON.stringify({ iss: humanDid, sub: agentDid, iat: 0, vc: { credentialSubject: { id: agentDid, over_21: false } } })
      ).toString("base64url");
      vcJwt = `${parts[0]}.${fakePayload}.${parts[2]}`;
    }
  }

  console.log(`\nScenario: ${scenario}`);
  console.log(`Human DID: ${humanDid}`);
  console.log(`Agent DID: ${agentDid}`);
  console.log(`Human public key (b64url): ${humanPublicKeyB64}`);

  // The agent prompt includes all context needed for it to work offline
  // It uses check_delegation which calls verifyCredentialJwt with the embedded key
  // (In a real deployment, the DID document would be fetched from Universal Resolver)
  const prompt = `
You are an AI agent trying to access age-restricted content.

Your DID: ${agentDid}
You have a Verifiable Credential (JWT): ${vcJwt}

The resource server requires:
1. The VC must be addressed to you (sub = your DID)
2. The VC must have claims: over_21=true, age_verified=true
3. The VC must not be expired
4. The VC signature must be valid

IMPORTANT: For this demo, the issuer DID (${humanDid}) is a local test DID.
Instead of calling resolve_did (which would fail for a local DID), use verify_credential
to check the VC structure and expiry only, then determine access based on:
- Is the VC addressed to you?
- Does it have the required claims?
- Is it expired?
- Note: signature verification against a local DID is not possible without the DID document,
  so for this demo, focus on structural and claim validation.

Report clearly: ACCESS GRANTED or ACCESS DENIED, and why.
`.trim();

  await runAgent(prompt);
}

main();

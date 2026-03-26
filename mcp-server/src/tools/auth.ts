/**
 * IO boundary for agent authentication tools.
 */
import { generateChallenge, verifyChallengeResponse, type ChallengeToken } from "../lib/challenge.js";
import { resolveDID } from "../lib/resolver.js";
import { extractEd25519Key } from "./verify.js";

export async function createChallengeTool(input: {
  agentDid: string;
  ttlSeconds?: number;
}): Promise<ChallengeToken> {
  return generateChallenge(input.agentDid, input.ttlSeconds);
}

export async function verifyAuthTool(input: {
  agentDid: string;
  nonce: string;
  issuedAt: number;
  signatureBase64url: string;
  expiresAt?: number;
}): Promise<{ authenticated: boolean; reason?: string }> {
  // Resolve agent DID to get their public key
  const resolution = await resolveDID(input.agentDid);
  if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      authenticated: false,
      reason: `Cannot resolve agent DID: ${resolution.didResolutionMetadata.error}`,
    };
  }

  const publicKey = extractEd25519Key(resolution.didDocument.verificationMethod ?? []);
  if (!publicKey) {
    return { authenticated: false, reason: "No Ed25519 key found in agent DID document" };
  }

  const token: ChallengeToken = {
    nonce: input.nonce,
    agentDid: input.agentDid,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt ?? input.issuedAt + 300,
  };

  const result = await verifyChallengeResponse(token, input.signatureBase64url, publicKey);
  return { authenticated: result.valid, reason: result.reason };
}

/**
 * Agent authentication via challenge-response. Pure, no IO.
 */
import { verify, fromBase64url } from "./crypto.js";
import { randomBytes } from "node:crypto";
import { toBase64url } from "./crypto.js";

export interface ChallengeToken {
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  agentDid: string;
}

export function generateChallenge(agentDid: string, ttlSeconds = 300): ChallengeToken {
  const nonce = toBase64url(randomBytes(32));
  const issuedAt = Math.floor(Date.now() / 1000);
  return { nonce, issuedAt, expiresAt: issuedAt + ttlSeconds, agentDid };
}

export function signingInput(token: ChallengeToken): Uint8Array {
  return new TextEncoder().encode(`${token.nonce}:${token.agentDid}:${token.issuedAt}`);
}

export function isChallengeExpired(token: ChallengeToken, nowSeconds?: number): boolean {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  return now >= token.expiresAt;
}

export async function verifyChallengeResponse(
  token: ChallengeToken,
  signatureBase64url: string,
  publicKey: Uint8Array,
  nowSeconds?: number
): Promise<{ valid: boolean; reason?: string }> {
  if (isChallengeExpired(token, nowSeconds)) {
    return { valid: false, reason: "Challenge expired" };
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = fromBase64url(signatureBase64url);
  } catch {
    return { valid: false, reason: "Invalid signature encoding" };
  }

  const input = signingInput(token);
  const valid = await verify(input, sigBytes, publicKey);
  if (!valid) {
    return { valid: false, reason: "Signature verification failed" };
  }

  return { valid: true };
}

/**
 * Delegation chain verification. Pure (keys passed in, no IO).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { toBase64url } from "./crypto.js";
import { verifyCredentialJwt, parseCredential, type VCPayload } from "./vc.js";

export interface ChainLink {
  vcJwt: string;
  issuerPublicKey: Uint8Array;
}

interface ChainEntry {
  issuer: string;
  subject: string;
}

export function extractDelegatedFrom(payload: VCPayload): string | null {
  const val = payload.vc.credentialSubject.delegatedFrom;
  return typeof val === "string" ? val : null;
}

function sha256base64url(input: string): string {
  return toBase64url(sha256(new TextEncoder().encode(input)));
}

export async function verifyDelegationChain(
  links: ChainLink[],
  leafAgentDid: string,
  maxDepth = 5
): Promise<{ valid: boolean; depth: number; chain?: ChainEntry[]; reason?: string }> {
  if (links.length === 0) {
    return { valid: false, depth: 0, reason: "Empty chain" };
  }

  if (links.length > maxDepth) {
    return { valid: false, depth: links.length, reason: `Chain depth ${links.length} exceeds max depth ${maxDepth}` };
  }

  const chain: ChainEntry[] = [];
  const seenIssuers = new Set<string>();
  let prevSubject: string | null = null;

  for (let i = 0; i < links.length; i++) {
    const { vcJwt, issuerPublicKey } = links[i];

    // Verify the signature and expiry
    const verifyResult = await verifyCredentialJwt(vcJwt, issuerPublicKey);
    if (!verifyResult.valid) {
      return { valid: false, depth: i + 1, reason: `Link ${i}: ${verifyResult.reason}` };
    }

    const payload = parseCredential(vcJwt)!;
    const issuer = payload.iss;
    const subject = payload.sub;

    // Circular reference detection
    if (seenIssuers.has(issuer)) {
      return { valid: false, depth: i + 1, reason: `Issuer ${issuer} already seen — circular reference detected` };
    }
    seenIssuers.add(issuer);

    // Chain continuity: each issuer must equal previous subject
    if (prevSubject !== null && issuer !== prevSubject) {
      return {
        valid: false,
        depth: i + 1,
        reason: `Link ${i}: issuer (${issuer}) does not match previous subject (${prevSubject})`,
      };
    }

    // Verify delegatedFrom hash (for links beyond the first)
    if (i > 0) {
      const parentJwt = links[i - 1].vcJwt;
      const expectedHash = sha256base64url(parentJwt);
      const actualHash = extractDelegatedFrom(payload);
      // Only enforce if delegatedFrom is present — it's optional for root delegation
      if (actualHash !== null && actualHash !== expectedHash) {
        return {
          valid: false,
          depth: i + 1,
          reason: `Link ${i}: delegatedFrom hash mismatch`,
        };
      }
    }

    chain.push({ issuer, subject });
    prevSubject = subject;
  }

  // Leaf subject must equal leafAgentDid
  const leafSubject = chain[chain.length - 1].subject;
  if (leafSubject !== leafAgentDid) {
    return {
      valid: false,
      depth: links.length,
      reason: `Leaf subject (${leafSubject}) does not match expected leaf agent DID (${leafAgentDid})`,
    };
  }

  return { valid: true, depth: links.length, chain };
}

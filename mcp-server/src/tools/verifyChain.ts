/**
 * IO boundary for delegation chain verification.
 */
import { verifyDelegationChain, type ChainLink } from "../lib/chain.js";
import { resolveDID } from "../lib/resolver.js";
import { extractEd25519Key } from "./verify.js";
import { parseCredential } from "../lib/vc.js";

export async function verifyDelegationChainTool(input: {
  vcChain: string[];
  agentDid: string;
}): Promise<{ authorized: boolean; depth: number; reason: string; chain?: Array<{ issuer: string; subject: string }> }> {
  const { vcChain, agentDid } = input;

  if (vcChain.length === 0) {
    return { authorized: false, depth: 0, reason: "Empty chain" };
  }

  // Resolve each issuer DID and assemble ChainLink array
  const links: ChainLink[] = [];

  for (let i = 0; i < vcChain.length; i++) {
    const vcJwt = vcChain[i];
    const payload = parseCredential(vcJwt);
    if (!payload) {
      return { authorized: false, depth: i, reason: `Link ${i}: malformed JWT` };
    }

    const resolution = await resolveDID(payload.iss);
    if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
      return {
        authorized: false,
        depth: i,
        reason: `Link ${i}: cannot resolve issuer DID ${payload.iss}: ${resolution.didResolutionMetadata.error}`,
      };
    }

    const publicKey = extractEd25519Key(resolution.didDocument.verificationMethod ?? []);
    if (!publicKey) {
      return {
        authorized: false,
        depth: i,
        reason: `Link ${i}: no Ed25519 key in DID document for ${payload.iss}`,
      };
    }

    links.push({ vcJwt, issuerPublicKey: publicKey });
  }

  const result = await verifyDelegationChain(links, agentDid);
  return {
    authorized: result.valid,
    depth: result.depth,
    reason: result.reason ?? `Delegation chain verified for agent ${agentDid}`,
    chain: result.chain,
  };
}

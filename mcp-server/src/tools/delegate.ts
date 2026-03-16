import { parseCredential, verifyCredentialJwt } from "../lib/vc.js";
import { resolveDID } from "../lib/resolver.js";
import { extractEd25519Key } from "./verify.js";

export interface DelegationResult {
  authorized: boolean;
  reason: string;
}

export interface CheckDelegationInput {
  agentDid: string;
  requestedAction: string;
  /** JWT-format VC */
  vcJwt: string;
  /** Claims that must be present and truthy for authorization */
  requiredClaims?: Record<string, unknown>;
}

export async function checkDelegation(
  input: CheckDelegationInput
): Promise<DelegationResult> {
  const { agentDid, requestedAction, vcJwt, requiredClaims = {} } = input;

  // 1. Parse the VC
  const payload = parseCredential(vcJwt);
  if (!payload) {
    return { authorized: false, reason: "Malformed VC JWT" };
  }

  // 2. Check the VC is addressed to this agent
  if (payload.sub !== agentDid) {
    return {
      authorized: false,
      reason: `VC subject (${payload.sub}) does not match agent DID (${agentDid})`,
    };
  }

  // 3. Resolve the issuer DID
  const resolution = await resolveDID(payload.iss);
  if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      authorized: false,
      reason: `Cannot resolve issuer DID: ${resolution.didResolutionMetadata.error}`,
    };
  }

  // 4. Extract public key + verify signature + check expiry
  const publicKey = extractEd25519Key(
    resolution.didDocument.verificationMethod ?? []
  );
  if (!publicKey) {
    return {
      authorized: false,
      reason: "No Ed25519 key found in issuer DID document",
    };
  }

  const verifyResult = await verifyCredentialJwt(vcJwt, publicKey);
  if (!verifyResult.valid) {
    return { authorized: false, reason: verifyResult.reason ?? "Invalid VC" };
  }

  // 5. Check required claims
  const credentialSubject = payload.vc.credentialSubject;
  for (const [key, expectedValue] of Object.entries(requiredClaims)) {
    if (credentialSubject[key] !== expectedValue) {
      return {
        authorized: false,
        reason: `Required claim '${key}' not satisfied (expected ${JSON.stringify(expectedValue)}, got ${JSON.stringify(credentialSubject[key])})`,
      };
    }
  }

  return {
    authorized: true,
    reason: `Agent ${agentDid} authorized for action '${requestedAction}' by issuer ${payload.iss}`,
  };
}

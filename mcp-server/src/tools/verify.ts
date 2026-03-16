import { parseCredential, verifyCredentialJwt, type VerifyResult } from "../lib/vc.js";
import { resolveDID, type VerificationMethod } from "../lib/resolver.js";
import { fromBase64url } from "../lib/crypto.js";

/**
 * Verify a VC JWT by:
 * 1. Parsing the JWT to find the issuer DID
 * 2. Resolving the issuer DID document
 * 3. Extracting the Ed25519 public key
 * 4. Verifying the JWT signature
 */
export async function verifyCredentialTool(jwt: string): Promise<VerifyResult> {
  const payload = parseCredential(jwt);
  if (!payload) {
    return { valid: false, reason: "Malformed JWT" };
  }

  const resolution = await resolveDID(payload.iss);
  if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      valid: false,
      reason: `Could not resolve issuer DID: ${resolution.didResolutionMetadata.error}`,
    };
  }

  const publicKey = extractEd25519Key(
    resolution.didDocument.verificationMethod ?? []
  );
  if (!publicKey) {
    return {
      valid: false,
      reason: "No Ed25519 verification key found in DID document",
    };
  }

  return verifyCredentialJwt(jwt, publicKey);
}

/**
 * Extract Ed25519 public key bytes from verification methods.
 * Supports publicKeyJwk (crv: Ed25519) and publicKeyMultibase (z-prefix base58btc).
 */
export function extractEd25519Key(
  methods: VerificationMethod[]
): Uint8Array | null {
  for (const method of methods) {
    // JWK format
    if (
      method.publicKeyJwk &&
      method.publicKeyJwk.crv === "Ed25519" &&
      typeof method.publicKeyJwk.x === "string"
    ) {
      return fromBase64url(method.publicKeyJwk.x);
    }

    // Multibase (z = base58btc) — Ed25519 public key multicodec prefix is 0xed 0x01
    if (method.publicKeyMultibase && method.publicKeyMultibase.startsWith("z")) {
      const raw = base58Decode(method.publicKeyMultibase.slice(1));
      if (raw && raw.length >= 2) {
        return raw.slice(2); // strip multicodec prefix
      }
    }
  }
  return null;
}

/** Minimal base58btc decoder (Bitcoin alphabet) */
function base58Decode(encoded: string): Uint8Array | null {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt(0);
  for (const ch of encoded) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    n = n * BigInt(58) + BigInt(idx);
  }
  // Convert bigint to bytes
  const hex = n.toString(16).padStart(2, "0");
  const padded = hex.length % 2 ? "0" + hex : hex;
  const bytes = new Uint8Array(padded.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  // Prepend leading zero bytes for leading '1's
  let leading = 0;
  for (const ch of encoded) {
    if (ch === "1") leading++;
    else break;
  }
  const result = new Uint8Array(leading + bytes.length);
  result.set(bytes, leading);
  return result;
}

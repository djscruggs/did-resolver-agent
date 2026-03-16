import { issueCredential, type VCClaims, type VerifiableCredential } from "../lib/vc.js";
import { fromBase64url, type KeyPair } from "../lib/crypto.js";

export interface IssueInput {
  subjectDid: string;
  claims: VCClaims;
  issuerDid: string;
  /** Base64url-encoded Ed25519 private key (32 bytes) */
  privateKeyBase64url: string;
  /** Optional TTL in seconds */
  expiresInSeconds?: number;
}

export async function issueCredentialTool(
  input: IssueInput
): Promise<VerifiableCredential> {
  const privateKey = fromBase64url(input.privateKeyBase64url);
  const { getPublicKeyAsync } = await import("@noble/ed25519");
  const publicKey = await getPublicKeyAsync(privateKey);
  const keyPair: KeyPair = { privateKey, publicKey };
  return issueCredential(
    input.subjectDid,
    input.claims,
    input.issuerDid,
    keyPair,
    input.expiresInSeconds
  );
}

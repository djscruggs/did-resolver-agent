import { issueCredential, type VCClaims, type VerifiableCredential, type CredentialStatus } from "../lib/vc.js";
import { fromBase64url, type KeyPair } from "../lib/crypto.js";

export interface IssueInput {
  subjectDid: string;
  claims: VCClaims;
  issuerDid: string;
  /** Base64url-encoded Ed25519 private key (32 bytes) */
  privateKeyBase64url: string;
  /** Optional TTL in seconds */
  expiresInSeconds?: number;
  /** Optional audience restriction */
  audience?: string | string[];
  /** Optional delegation chain reference */
  delegatedFrom?: string;
  /** Optional credential status for revocation support */
  credentialStatus?: CredentialStatus;
}

export async function issueCredentialTool(
  input: IssueInput
): Promise<VerifiableCredential> {
  const privateKey = fromBase64url(input.privateKeyBase64url);
  const { getPublicKeyAsync } = await import("@noble/ed25519");
  const publicKey = await getPublicKeyAsync(privateKey);
  const keyPair: KeyPair = { privateKey, publicKey };

  // Inject delegatedFrom into claims if present
  const claims: VCClaims = input.delegatedFrom
    ? { ...input.claims, delegatedFrom: input.delegatedFrom }
    : input.claims;

  return issueCredential(
    input.subjectDid,
    claims,
    input.issuerDid,
    keyPair,
    input.expiresInSeconds,
    {
      audience: input.audience,
      credentialStatus: input.credentialStatus,
    }
  );
}

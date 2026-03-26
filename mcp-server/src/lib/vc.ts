/**
 * Pure VC logic: issue, parse, verify JWT-format VCs.
 * No IO — testable in isolation.
 */
import { sign, verify, toBase64url, fromBase64url, type KeyPair } from "./crypto.js";

export interface VCClaims {
  age_verified?: boolean;
  over_21?: boolean;
  [key: string]: unknown;
}

export interface VerifiableCredential {
  /** JWT string */
  jwt: string;
}

export interface CredentialStatus {
  id: string;
  type: "StatusList2021Entry";
  statusPurpose: string;
  statusListIndex: string;
  statusListCredential: string;
}

export interface VCPayload {
  iss: string;       // issuer DID
  sub: string;       // subject DID (agent)
  iat: number;       // issued-at (unix seconds)
  exp?: number;      // expiry (unix seconds)
  aud?: string | string[];  // audience restriction
  vc: {
    "@context": string[];
    type: string[];
    credentialSubject: VCClaims & { id: string };
    credentialStatus?: CredentialStatus;
  };
}

export interface VerifyResult {
  valid: boolean;
  issuer?: string;
  subject?: string;
  claims?: VCClaims;
  expires?: string | null;
  reason?: string;
}

function encodeJwtPart(obj: unknown): string {
  return toBase64url(
    new TextEncoder().encode(JSON.stringify(obj))
  );
}

function decodeJwtPart(part: string): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64url(part)));
}

export async function issueCredential(
  subjectDid: string,
  claims: VCClaims,
  issuerDid: string,
  keyPair: KeyPair,
  expiresInSeconds?: number,
  options?: {
    audience?: string | string[];
    credentialStatus?: CredentialStatus;
  }
): Promise<VerifiableCredential> {
  const now = Math.floor(Date.now() / 1000);
  const payload: VCPayload = {
    iss: issuerDid,
    sub: subjectDid,
    iat: now,
    ...(expiresInSeconds ? { exp: now + expiresInSeconds } : {}),
    ...(options?.audience ? { aud: options.audience } : {}),
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      credentialSubject: { id: subjectDid, ...claims },
      ...(options?.credentialStatus ? { credentialStatus: options.credentialStatus } : {}),
    },
  };

  const header = encodeJwtPart({ alg: "EdDSA", typ: "JWT" });
  const body = encodeJwtPart(payload);
  const signingInput = `${header}.${body}`;
  const sigBytes = await sign(
    new TextEncoder().encode(signingInput),
    keyPair.privateKey
  );

  const jwt = `${signingInput}.${toBase64url(sigBytes)}`;
  return { jwt };
}

export function parseCredential(jwt: string): VCPayload | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    return decodeJwtPart(parts[1]) as VCPayload;
  } catch {
    return null;
  }
}

/**
 * Verify a VC JWT against a raw Ed25519 public key.
 * Caller is responsible for fetching the public key from the DID document.
 */
export async function verifyCredentialJwt(
  jwt: string,
  publicKey: Uint8Array,
  expectedAudience?: string
): Promise<VerifyResult> {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return { valid: false, reason: "Malformed JWT" };
  }

  const [header, body, sigStr] = parts;
  const signingInput = `${header}.${body}`;

  let payload: VCPayload;
  try {
    payload = decodeJwtPart(body) as VCPayload;
  } catch {
    return { valid: false, reason: "Cannot decode JWT payload" };
  }

  const sigBytes = fromBase64url(sigStr);
  const signingBytes = new TextEncoder().encode(signingInput);
  const valid = await verify(signingBytes, sigBytes, publicKey);

  if (!valid) {
    return { valid: false, reason: "Signature verification failed" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp !== undefined && payload.exp < now) {
    return {
      valid: false,
      issuer: payload.iss,
      subject: payload.sub,
      reason: `Credential expired at ${new Date(payload.exp * 1000).toISOString()}`,
    };
  }

  if (expectedAudience !== undefined) {
    const aud = payload.aud;
    if (!aud) {
      return { valid: false, issuer: payload.iss, subject: payload.sub, reason: "VC has no audience but expectedAudience was set" };
    }
    const audArray = Array.isArray(aud) ? aud : [aud];
    if (!audArray.includes(expectedAudience)) {
      return { valid: false, issuer: payload.iss, subject: payload.sub, reason: `Audience mismatch: expected '${expectedAudience}' not in ${JSON.stringify(aud)}` };
    }
  }

  const { id: _id, ...claims } = payload.vc.credentialSubject;

  return {
    valid: true,
    issuer: payload.iss,
    subject: payload.sub,
    claims,
    expires: payload.exp
      ? new Date(payload.exp * 1000).toISOString()
      : null,
  };
}

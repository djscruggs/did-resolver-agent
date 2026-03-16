import { generateKeyPair } from "../lib/crypto.js";
import { issueCredential, parseCredential, verifyCredentialJwt } from "../lib/vc.js";

const ISSUER_DID = "did:key:z6MkHuman";
const AGENT_DID = "did:key:z6MkAgent";

describe("VC: issue + verify", () => {
  it("issues a valid credential and verifies it", async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID,
      { age_verified: true, over_21: true },
      ISSUER_DID,
      kp
    );
    expect(vc.jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    const result = await verifyCredentialJwt(vc.jwt, kp.publicKey);
    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(ISSUER_DID);
    expect(result.subject).toBe(AGENT_DID);
    expect(result.claims).toMatchObject({ age_verified: true, over_21: true });
  });

  it("rejects a tampered credential", async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(AGENT_DID, { over_21: true }, ISSUER_DID, kp);

    // tamper: replace body with different claims
    const parts = vc.jwt.split(".");
    const fakeBody = Buffer.from(
      JSON.stringify({ iss: ISSUER_DID, sub: AGENT_DID, iat: 0, vc: { credentialSubject: { id: AGENT_DID, over_21: false } } })
    ).toString("base64url");
    const tampered = `${parts[0]}.${fakeBody}.${parts[2]}`;

    const result = await verifyCredentialJwt(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("rejects an expired credential", async () => {
    const kp = await generateKeyPair();
    // expire immediately (1 second TTL, then wait is not needed — use negative TTL trick)
    const vc = await issueCredential(AGENT_DID, { over_21: true }, ISSUER_DID, kp, -1);

    const result = await verifyCredentialJwt(vc.jwt, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("parseCredential extracts payload", async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(AGENT_DID, { age_verified: true }, ISSUER_DID, kp);
    const payload = parseCredential(vc.jwt);
    expect(payload?.iss).toBe(ISSUER_DID);
    expect(payload?.sub).toBe(AGENT_DID);
  });

  it("parseCredential returns null for malformed JWT", () => {
    expect(parseCredential("not.a.valid.jwt.extra")).toBeNull();
    expect(parseCredential("onlytwoparts.nope")).toBeNull();
  });
});

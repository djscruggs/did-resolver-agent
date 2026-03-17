import { jest } from "@jest/globals";
import type { ResolutionResult } from "../lib/resolver.js";

// ESM-native mock — must be called before dynamic imports
const mockResolveDID = jest.fn<() => Promise<ResolutionResult>>();
jest.unstable_mockModule("../lib/resolver.js", () => ({
  resolveDID: mockResolveDID,
}));

// Dynamic imports after mock registration
const { generateKeyPair, toBase64url } = await import("../lib/crypto.js");
const { issueCredential } = await import("../lib/vc.js");
const { checkDelegation } = await import("../tools/delegate.js");

const ISSUER_DID = "did:key:z6MkHuman";
const AGENT_DID = "did:key:z6MkAgent";
const ACTION = "access:age-restricted-content";

async function makeVC(
  kp: Awaited<ReturnType<typeof generateKeyPair>>,
  claims: Record<string, unknown> = { age_verified: true, over_21: true },
  expiresInSeconds?: number
) {
  return issueCredential(AGENT_DID, claims, ISSUER_DID, kp, expiresInSeconds);
}

function mockResolver(kp: Awaited<ReturnType<typeof generateKeyPair>>) {
  const resolution: ResolutionResult = {
    didDocument: {
      id: ISSUER_DID,
      verificationMethod: [
        {
          id: `${ISSUER_DID}#key-1`,
          type: "JsonWebKey2020",
          controller: ISSUER_DID,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(kp.publicKey) },
        },
      ],
    },
    didResolutionMetadata: {},
  };
  mockResolveDID.mockResolvedValue(resolution);
}

describe("checkDelegation", () => {
  let kp: Awaited<ReturnType<typeof generateKeyPair>>;

  beforeEach(async () => {
    kp = await generateKeyPair();
    jest.clearAllMocks();
  });

  it("authorizes when VC is valid and all required claims satisfied", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { age_verified: true, over_21: true },
    });
    expect(result.authorized).toBe(true);
    expect(result.reason).toMatch(AGENT_DID);
  });

  it("authorizes with no required claims specified", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(true);
  });

  it("denies when VC subject does not match agent DID", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: "did:key:z6MkSomeoneElse",
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });

  it("denies when required claim is missing from VC", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { age_verified: true }); // no over_21
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { over_21: true },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it("denies when required claim has wrong value", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: false });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { over_21: true },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it("denies when VC is expired", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: true }, -1);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("denies when VC payload is tampered", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: true });
    const parts = vc.jwt.split(".");
    const fakeBody = Buffer.from(
      JSON.stringify({ iss: ISSUER_DID, sub: AGENT_DID, iat: 0, vc: { credentialSubject: { id: AGENT_DID, over_21: false } } })
    ).toString("base64url");
    const tampered = `${parts[0]}.${fakeBody}.${parts[2]}`;
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: tampered,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("denies when DID resolution fails", async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: { error: "notFound" },
    });
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/resolve/i);
  });

  it("denies when DID document has no Ed25519 key", async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: ISSUER_DID,
        verificationMethod: [
          {
            id: `${ISSUER_DID}#key-1`,
            type: "RsaVerificationKey2018",
            controller: ISSUER_DID,
            publicKeyBase58: "someRsaKey",
          },
        ],
      },
      didResolutionMetadata: {},
    });
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/Ed25519/);
  });

  it("denies malformed JWT", async () => {
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: "not.a.valid.jwt.extra",
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });
});

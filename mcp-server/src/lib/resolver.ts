/**
 * Universal Resolver client.
 * IO boundary — mocked in tests.
 */

const UNIVERSAL_RESOLVER_BASE = "https://dev.uniresolver.io/1.0/identifiers";

export interface DIDDocument {
  id: string;
  verificationMethod?: VerificationMethod[];
  authentication?: (string | VerificationMethod)[];
  assertionMethod?: (string | VerificationMethod)[];
  [key: string]: unknown;
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase?: string;
  publicKeyJwk?: Record<string, unknown>;
  publicKeyBase58?: string;
}

export interface ResolutionResult {
  didDocument: DIDDocument | null;
  didResolutionMetadata: {
    error?: string;
    [key: string]: unknown;
  };
}

export async function resolveDID(did: string): Promise<ResolutionResult> {
  const url = `${UNIVERSAL_RESOLVER_BASE}/${encodeURIComponent(did)}`;
  const res = await fetch(url, {
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    return {
      didDocument: null,
      didResolutionMetadata: {
        error: `HTTP ${res.status}: ${res.statusText}`,
      },
    };
  }

  const body = await res.json() as ResolutionResult;
  return body;
}

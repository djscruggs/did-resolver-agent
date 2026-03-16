import { resolveDID } from "../lib/resolver.js";
import type { DIDDocument } from "../lib/resolver.js";

export interface ResolveResult {
  didDocument: DIDDocument | null;
  error?: string;
}

export async function resolveDIDTool(did: string): Promise<ResolveResult> {
  const result = await resolveDID(did);
  if (result.didResolutionMetadata.error) {
    return { didDocument: null, error: result.didResolutionMetadata.error as string };
  }
  return { didDocument: result.didDocument };
}

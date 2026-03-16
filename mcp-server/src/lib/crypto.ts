/**
 * Pure crypto utilities: key generation, signing, verification (Ed25519).
 * No IO — testable in isolation.
 */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

// noble/ed25519 v2 requires sha512 to be set
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export async function generateKeyPair(): Promise<KeyPair> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

export async function sign(
  payload: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return ed.signAsync(payload, privateKey);
}

export async function verify(
  payload: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, payload, publicKey);
  } catch {
    return false;
  }
}

export function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function fromBase64url(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(base64, "base64"));
}

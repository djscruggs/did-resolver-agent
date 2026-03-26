/**
 * StatusList2021 revocation checking. Pure (takes already-fetched data).
 */
import { gunzipSync } from "node:zlib";

export function decodeStatusList(encodedList: string): Uint8Array {
  // base64url → Buffer → gunzip
  const compressed = Buffer.from(encodedList, "base64url");
  const decompressed = gunzipSync(compressed);
  return new Uint8Array(decompressed);
}

export function isRevoked(decoded: Uint8Array, index: number): boolean {
  const byteIndex = Math.floor(index / 8);
  if (byteIndex >= decoded.length) return false;
  const bitIndex = 7 - (index % 8); // MSB first
  return (decoded[byteIndex] & (1 << bitIndex)) !== 0;
}

export function checkRevocationStatus(
  encodedList: string,
  indexStr: string
): { revoked: boolean; reason?: string } {
  const decoded = decodeStatusList(encodedList);
  const index = parseInt(indexStr, 10);
  const revoked = isRevoked(decoded, index);
  if (revoked) {
    return { revoked: true, reason: `Credential at index ${index} has been revoked` };
  }
  return { revoked: false };
}

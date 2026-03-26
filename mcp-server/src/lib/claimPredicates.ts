/**
 * Predicate-based claim checking. Pure, no IO.
 */

export type ScalarValue = string | number | boolean | null;

export interface PredicateOperators {
  $eq?: ScalarValue;
  $ne?: ScalarValue;
  $lt?: number;
  $lte?: number;
  $gt?: number;
  $gte?: number;
  $in?: ScalarValue[];
  $nin?: ScalarValue[];
}

export type ClaimPredicate = ScalarValue | PredicateOperators;

function isPredicateOperators(p: ClaimPredicate): p is PredicateOperators {
  return p !== null && typeof p === "object" && !Array.isArray(p);
}

export function evaluatePredicate(actual: unknown, predicate: ClaimPredicate): boolean {
  if (!isPredicateOperators(predicate)) {
    return actual === predicate;
  }

  const ops = predicate;

  if ("$eq" in ops && actual !== ops.$eq) return false;
  if ("$ne" in ops && actual === ops.$ne) return false;

  if ("$lt" in ops) {
    if (typeof actual !== "number") return false;
    if (actual >= ops.$lt!) return false;
  }
  if ("$lte" in ops) {
    if (typeof actual !== "number") return false;
    if (actual > ops.$lte!) return false;
  }
  if ("$gt" in ops) {
    if (typeof actual !== "number") return false;
    if (actual <= ops.$gt!) return false;
  }
  if ("$gte" in ops) {
    if (typeof actual !== "number") return false;
    if (actual < ops.$gte!) return false;
  }

  if ("$in" in ops && !ops.$in!.includes(actual as ScalarValue)) return false;
  if ("$nin" in ops && ops.$nin!.includes(actual as ScalarValue)) return false;

  return true;
}

export type CheckClaimsResult =
  | { satisfied: true }
  | { satisfied: false; failedKey: string; reason: string };

export function checkClaims(
  subject: Record<string, unknown>,
  required: Record<string, ClaimPredicate>
): CheckClaimsResult {
  for (const [key, predicate] of Object.entries(required)) {
    const actual = subject[key];
    if (!evaluatePredicate(actual, predicate)) {
      return {
        satisfied: false,
        failedKey: key,
        reason: `Claim '${key}' not satisfied (got ${JSON.stringify(actual)}, predicate: ${JSON.stringify(predicate)})`,
      };
    }
  }
  return { satisfied: true };
}

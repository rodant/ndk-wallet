/**
 * Deterministic Cashu Wallet Info (kind 17376)
 *
 * This module defines the event kind and data structures used by ndk-wallet
 * to carry BIP-39 seed and per-mint/keyset deterministic counter state.
 *
 * Note:
 * - We intentionally keep this kind definition inside ndk-wallet (not in ndk core).
 * - Content is expected to be NIP-44 encrypted when published.
 */

export const DeterministicCashuWalletInfoKind: number = 17376;

/**
 * Canonical key format for counters map:
 *   "<normalized-mint>|<keyset-id>"
 *
 * - normalized-mint must be a canonical, normalized URL string as decided by the client:
 *   - lowercase scheme/host, strip default ports, remove query/fragment,
 *   - normalize path (no trailing slash unless root), preserve scheme (http vs https),
 *   - apply IDNA/punycode normalization if needed.
 * - keyset-id is the identifier issued by the mint (kept as-is; case-sensitive).
 * - The pipe character '|' is the reserved delimiter between mint and keyset-id.
 */
export type DeterministicCashuCounters = Record<string, number>;

/**
 * Decrypted JSON content schema for DeterministicCashuWalletInfoKind (17376).
 *
 * Example (conceptual):
 * {
 *   "bip39seed": "<hex>",
 *   "counters": {
 *     "<normalized-mint>|<keyset-id>": 0
 *   }
 * }
 */
export interface DeterministicCashuWalletInfoContent {
    bip39seed: string; // hex-encoded BIP-39 seed (or implementation-defined key bytes)
    counters: DeterministicCashuCounters;
}

/**
 * Placeholder for future parsing/validation helpers.
 * Implementations should:
 * - Decrypt (NIP-44) then JSON.parse
 * - Validate 'bip39seed' is hex and 'counters' is a map of non-negative integers
 * - Enforce canonical key format "<normalized-mint>|<keyset-id>"
 */
export function isDeterministicCashuWalletInfoContent(value: unknown): value is DeterministicCashuWalletInfoContent {
    if (typeof value !== "object" || value === null) return false;
    const v = value as Partial<DeterministicCashuWalletInfoContent>;
    if (typeof v.bip39seed !== "string") return false;
    if (!v.counters || typeof v.counters !== "object") return false;

    // basic counters validation
    for (const [k, n] of Object.entries(v.counters)) {
        if (typeof k !== "string") return false;
        if (typeof n !== "number" || !Number.isInteger(n) || n < 0) return false;
        if (!k.includes("|")) return false; // must contain delimiter
    }
    return true;
}
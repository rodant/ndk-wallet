/**
 * Deterministic Cashu counters: URL normalization and counter-key helpers.
 *
 * Key format:
 *   "<normalized-mint>|<keyset-id>"
 *
 * Normalization rules for <normalized-mint>:
 * - Protocol must be http or https (lowercased)
 * - Hostname lowercased (IDNA normalization is delegated to URL parser)
 * - Username/password removed
 * - Query parameters removed
 * - Fragment removed
 * - Default ports removed (http:80, https:443); non-default ports preserved
 * - Path normalized:
 *   - "/" for root
 *   - no trailing slash for non-root paths
 *
 * The pipe character "|" is reserved as a delimiter and MUST NOT appear
 * in either the normalized mint or the keyset id.
 */

export type CounterKey = string;

export const COUNTER_KEY_DELIMITER = "|";

/**
 * Normalize a mint URL to a canonical, stable representation:
 * - Only http/https are accepted
 * - Lowercase scheme and host
 * - Strip username/password, query and fragment
 * - Strip default ports (http:80, https:443)
 * - Normalize path:
 *   - "/" for root
 *   - no trailing slash for non-root
 *
 * Throws on invalid URLs or unsupported protocols.
 */
export function normalizeMintUrl(input: string): string {
    let u: URL;
    try {
        u = new URL(input);
    } catch {
        throw new Error(`Invalid mint URL: ${input}`);
    }

    if (u.protocol !== "http:" && u.protocol !== "https:") {
        throw new Error(`Unsupported mint URL protocol: ${u.protocol}`);
    }

    // Lowercase scheme and host
    const protocol = u.protocol.toLowerCase();
    const hostname = u.hostname.toLowerCase();

    // Explicitly drop userinfo, query and fragment
    // Note: we rebuild the URL string manually, but we still clear these for clarity.
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";

    // Strip default ports
    let port = u.port;
    if ((protocol === "http:" && port === "80") || (protocol === "https:" && port === "443")) {
        port = "";
    }

    // Normalize path
    let pathname = u.pathname || "/";
    if (pathname === "") pathname = "/";
    if (pathname !== "/" && pathname.endsWith("/")) {
        pathname = pathname.slice(0, -1);
    }

    // Build canonical string (no username/password, no query or fragment)
    const authority = port ? `${hostname}:${port}` : hostname;
    return `${protocol}//${authority}${pathname}`;
}

/**
 * Build a counter key from a (possibly non-normalized) mint URL and keyset id.
 * - Applies normalizeMintUrl() to the mint
 * - Validates that "|" is not present in either part
 */
export function buildCounterKey(mintUrl: string, keysetId: string): CounterKey {
    const normalizedMint = normalizeMintUrl(mintUrl);

    if (normalizedMint.includes(COUNTER_KEY_DELIMITER)) {
        throw new Error(`Normalized mint contains reserved delimiter "${COUNTER_KEY_DELIMITER}"`);
    }
    if (keysetId.includes(COUNTER_KEY_DELIMITER)) {
        throw new Error(`keysetId contains reserved delimiter "${COUNTER_KEY_DELIMITER}"`);
    }

    return `${normalizedMint}${COUNTER_KEY_DELIMITER}${keysetId}`;
}

/**
 * Validate whether a string matches the counter key format.
 * - Verifies delimiter position
 * - Verifies keyset id does not contain the delimiter
 * - Verifies mint part is a stable normalized URL (idempotent normalization)
 */
export function isValidCounterKey(key: string): boolean {
    if (typeof key !== "string") return false;
    const idx = key.indexOf(COUNTER_KEY_DELIMITER);
    if (idx <= 0) return false; // delimiter not found or at start

    const mint = key.slice(0, idx);
    const ksid = key.slice(idx + 1);

    if (!mint || !ksid) return false;
    // No nested delimiter allowed in either side
    if (ksid.includes(COUNTER_KEY_DELIMITER)) return false;

    try {
        // Re-normalize to ensure mint part is a canonical URL
        const re = normalizeMintUrl(mint);
        // It must be stable (idempotent)
        if (re !== mint) return false;
    } catch {
        return false;
    }

    return true;
}

/**
 * Parse a counter key into its components. Throws if invalid.
 */
export function parseCounterKey(key: string): { normalizedMint: string; keysetId: string } {
    if (!isValidCounterKey(key)) {
        throw new Error(`Invalid counter key: ${key}`);
    }
    const idx = key.indexOf(COUNTER_KEY_DELIMITER);
    const normalizedMint = key.slice(0, idx);
    const keysetId = key.slice(idx + 1);
    return { normalizedMint, keysetId };
}
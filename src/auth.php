<?php
/**
 * auth.php — REFACTORED (secure)
 *
 * Fixes two vulnerabilities found in the legacy version:
 *   1. Byte/character bound failure — legacy code used strlen() to cap
 *      key length at 256, but strlen() counts BYTES, not characters. In
 *      UTF-8 a character can be 1-4 bytes, so the same byte limit means a
 *      different real character count depending on the input, allowing
 *      multi-byte payloads to bypass or corrupt the intended boundary.
 *   2. MD5 password hashing — MD5 has no cost parameter (fast: billions
 *      of hashes/sec on GPUs) and the legacy code used it unsalted, so
 *      leaked hashes are trivially reversible via rainbow tables or
 *      brute force.
 *
 * Fix strategy:
 *   - Use mb_strlen($input, 'UTF-8') so the length check counts actual
 *     Unicode codepoints, not raw bytes — the boundary now measures the
 *     same thing regardless of character width.
 *   - Use password_hash()/password_verify() with PASSWORD_ARGON2ID, which
 *     is memory-hard and time-hard (forces every guess to consume a large
 *     memory region for a minimum time) and salts automatically per hash,
 *     defeating both parallel GPU cracking and precomputed rainbow tables.
 */

declare(strict_types=1);

/**
 * Validate a submitted credential's length using a true character count.
 *
 * @throws Exception if the input exceeds the allowed character boundary.
 */
function validateKeyLength(string $inputKey, int $maxChars = 256): void
{
    // mb_strlen decodes the byte stream into Unicode codepoints first,
    // so 256 always means 256 real characters, closing the multi-byte
    // truncation/bypass path that strlen() left open.
    if (mb_strlen($inputKey, 'UTF-8') > $maxChars) {
        throw new Exception('Credential exceeds maximum allowed length.');
    }
}

/**
 * Register/store a new staff credential using a memory-hard hash.
 */
function storeCredential(string $inputKey): string
{
    validateKeyLength($inputKey);

    // PASSWORD_ARGON2ID: memory-hardness + time-hardness make each guess
    // expensive to compute, and a random salt is generated automatically,
    // so identical inputs never produce identical stored hashes.
    return password_hash($inputKey, PASSWORD_ARGON2ID, [
        'memory_cost' => 1 << 17, // 128 MB
        'time_cost'   => 4,
        'threads'     => 2,
    ]);
}

/**
 * Verify a submitted credential against its stored Argon2id hash.
 */
function verifyCredential(string $inputKey, string $storedHash): bool
{
    try {
        validateKeyLength($inputKey);
    } catch (Exception $e) {
        // Treat an oversized/invalid input as a failed auth attempt,
        // not a crash — mirrors the isolated-failure handling used in
        // crypto_vault.php for tag-mismatch errors.
        return false;
    }

    return password_verify($inputKey, $storedHash);
}

// --- Example usage --------------------------------------------------------
// $inputKey   = $_POST['credential'] ?? '';
// $storedHash = fetchStoredHashForUser($physicianId); // from DB
//
// if (verifyCredential($inputKey, $storedHash)) {
//     echo 'Access Granted.';
// } else {
//     http_response_code(401);
//     echo 'Access Denied.';
// }

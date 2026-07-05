<?php
/**
 * crypto_vault.php — REFACTORED (secure)
 *
 * Fixes two vulnerabilities found in the legacy version:
 *   1. ECB mode leakage — legacy code encrypted fixed-size blocks
 *      independently with no chaining/randomness, so identical plaintext
 *      blocks always produced identical ciphertext blocks, leaking
 *      structural patterns in sensitive medical records.
 *   2. Hardcoded key — the encryption key was a literal string tracked in
 *      the PHP source (and therefore in git history), so anyone with
 *      repo access had the key permanently.
 *
 * Fix strategy:
 *   - Use AES-256-GCM, an AEAD (Authenticated Encryption with Associated
 *     Data) mode: a random IV per encryption removes the deterministic
 *     pattern leakage, and a 16-byte authentication tag lets the
 *     decrypting side detect tampering.
 *   - Load the key from an environment variable (APP_CRYPTO_KEY, defined
 *     in a git-ignored .env file) instead of hardcoding it in source.
 *   - Serialize as base64( IV[12] . ciphertext[N] . TAG[16] ) so a single
 *     string can be stored/transported, then reversed by slicing the
 *     first 12 bytes (IV) and last 16 bytes (tag) off on decrypt.
 *   - Treat a failed tag check as a caught, isolated exception — not an
 *     uncaught crash — so a single tampered record can't take down the
 *     whole request/process.
 */

declare(strict_types=1);

final class CryptoVaultException extends Exception {}

final class CryptoVault
{
    private string $key;

    public function __construct(?string $base64Key = null)
    {
        // Key is decoupled from source: read at runtime from the
        // environment (populated from .env, which is git-ignored — see
        // .gitignore and .env.example in this repo).
        $raw = $base64Key ?? getenv('APP_CRYPTO_KEY');

        if (!$raw) {
            throw new CryptoVaultException('APP_CRYPTO_KEY is not set.');
        }

        // Expected format: "base64:<32 raw bytes for AES-256>"
        $decoded = base64_decode(str_replace('base64:', '', $raw), true);

        if ($decoded === false || strlen($decoded) !== 32) {
            throw new CryptoVaultException('APP_CRYPTO_KEY must decode to exactly 32 bytes.');
        }

        $this->key = $decoded;
    }

    /**
     * Encrypt plaintext with AES-256-GCM and pack IV + ciphertext + tag
     * into a single base64 string: base64( IV[12] . ciphertext[N] . TAG[16] ).
     */
    public function encrypt(string $plaintext): string
    {
        // A fresh, unpredictable 12-byte IV is generated for EVERY call.
        // GCM's security guarantees only hold if the IV is never reused
        // under the same key — reuse leaks plaintext XORs and lets an
        // attacker forge authentication tags.
        $iv = random_bytes(12);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',   // no additional authenticated data
            16    // tag length in bytes
        );

        if ($ciphertext === false) {
            throw new CryptoVaultException('Encryption failed.');
        }

        // Fixed-order packing: IV (12 bytes) . ciphertext (N bytes) . tag (16 bytes)
        return base64_encode($iv . $ciphertext . $tag);
    }

    /**
     * Decrypt a blob produced by encrypt(). Throws a caught,
     * application-level exception on tamper/failure instead of letting
     * openssl's false-return propagate as an uncaught crash.
     */
    public function decrypt(string $blob): string
    {
        $raw = base64_decode($blob, true);

        if ($raw === false || strlen($raw) < 28) { // 12 (IV) + 16 (tag) minimum
            throw new CryptoVaultException('Malformed ciphertext blob.');
        }

        // Unpack in reverse: first 12 bytes = IV, last 16 bytes = tag,
        // whatever remains in the middle (variable length) = ciphertext.
        $iv         = substr($raw, 0, 12);
        $tag        = substr($raw, -16);
        $ciphertext = substr($raw, 12, -16);

        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        // openssl_decrypt() returns false (not a fatal error) when the
        // authentication tag doesn't match — i.e. the data was tampered
        // with or the wrong key/IV was used. We convert that into a
        // caught exception so the caller can isolate the failure instead
        // of crashing the process.
        if ($plaintext === false) {
            throw new CryptoVaultException('Authentication tag mismatch — data may be tampered.');
        }

        return $plaintext;
    }
}

// --- Example usage ---------------------------------------------------------
// try {
//     $vault = new CryptoVault();
//     $blob  = $vault->encrypt($illnessHistoryJson);
//     // ... store $blob in patient_records.illness_history ...
//
//     $plaintext = $vault->decrypt($blob);
// } catch (CryptoVaultException $e) {
//     // Isolated failure: log it, reject this record, continue serving
//     // other requests — do NOT let this bubble up as an uncaught crash.
//     error_log('CryptoVault failure: ' . $e->getMessage());
// }

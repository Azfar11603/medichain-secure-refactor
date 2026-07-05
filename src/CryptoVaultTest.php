<?php
/**
 * CryptoVaultTest.php
 *
 * PHPUnit suite asserting the three runtime states described in Section 3.2:
 *   1. Clean encrypt -> decrypt round-trip returns the original plaintext.
 *   2. A tampered ciphertext throws the expected AEAD exception (caught,
 *      not an unhandled crash).
 *   3. Argon2id credential verification returns true/false correctly for
 *      matching/non-matching input.
 *
 * Run with: ./vendor/bin/phpunit CryptoVaultTest.php
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/crypto_vault.php';
require_once __DIR__ . '/auth.php';

final class CryptoVaultTest extends TestCase
{
    private CryptoVault $vault;

    protected function setUp(): void
    {
        // Fixed 32-byte test key (not the real production key).
        $testKey = base64_encode(str_repeat('A', 32));
        $this->vault = new CryptoVault('base64:' . $testKey);
    }

    /** State 1: clean encrypt -> decrypt round-trip. */
    public function testEncryptDecryptRoundTrip(): void
    {
        $plaintext = 'Patient diagnosis: Type 2 Diabetes';

        $blob = $this->vault->encrypt($plaintext);
        $recovered = $this->vault->decrypt($blob);

        $this->assertSame($plaintext, $recovered);
    }

    /** State 2: tampered ciphertext must throw, not silently decrypt garbage. */
    public function testTamperedCiphertextThrowsException(): void
    {
        $blob = $this->vault->encrypt('Opioid dosage: 40mg');

        $raw = base64_decode($blob, true);
        // Flip a byte inside the ciphertext region (after the 12-byte IV).
        $raw[15] = chr(ord($raw[15]) ^ 0xFF);
        $tamperedBlob = base64_encode($raw);

        $this->expectException(CryptoVaultException::class);
        $this->vault->decrypt($tamperedBlob);
    }

    /** State 3a: Argon2id verify returns true for the correct credential. */
    public function testCredentialVerifySucceedsForCorrectInput(): void
    {
        $hash = storeCredential('correct-horse-battery-staple');
        $this->assertTrue(verifyCredential('correct-horse-battery-staple', $hash));
    }

    /** State 3b: Argon2id verify returns false for an incorrect credential. */
    public function testCredentialVerifyFailsForIncorrectInput(): void
    {
        $hash = storeCredential('correct-horse-battery-staple');
        $this->assertFalse(verifyCredential('wrong-guess', $hash));
    }
}

<?php

declare(strict_types=1);

namespace App\Service\Security;

use SensitiveParameter;

/**
 * Libsodium secretbox (XSalsa20-Poly1305) implementation of EncryptionServiceInterface.
 */
final readonly class SodiumEncryptionService implements EncryptionServiceInterface
{
    private string $decodedMasterKey;

    /**
     * @throws \InvalidArgumentException If the master encryption key is not a valid 32-byte Base64 string
     */
    public function __construct(
        #[SensitiveParameter]
        string $vaultEncryptionKey,
    ) {
        $decodedKey = base64_decode(trim($vaultEncryptionKey), true);

        if (false === $decodedKey || \SODIUM_CRYPTO_SECRETBOX_KEYBYTES !== \strlen($decodedKey)) {
            throw new \InvalidArgumentException(\sprintf(
                'Invalid VAULT_ENCRYPTION_KEY: expected a Base64-encoded %d-byte key.',
                \SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
            ));
        }

        $this->decodedMasterKey = $decodedKey;
    }

    public function encrypt(#[SensitiveParameter] string $plainText): string
    {
        try {
            $nonce = random_bytes(\SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plainText, $nonce, $this->decodedMasterKey);
            $payload = base64_encode($nonce . $ciphertext);

            sodium_memzero($nonce);
            sodium_memzero($ciphertext);

            return $payload;
        } catch (\Throwable $exception) {
            throw new \RuntimeException('Failed to encrypt sensitive data.', 0, $exception);
        }
    }

    public function decrypt(string $encryptedPayload): string
    {
        $decoded = base64_decode($encryptedPayload, true);

        if (false === $decoded) {
            throw new \InvalidArgumentException('Invalid encrypted payload: malformed Base64 data.');
        }

        $minimumLength = \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + \SODIUM_CRYPTO_SECRETBOX_MACBYTES;

        if (\strlen($decoded) < $minimumLength) {
            throw new \InvalidArgumentException('Invalid encrypted payload: data is truncated or corrupted.');
        }

        $nonce = substr($decoded, 0, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($decoded, \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        try {
            $plainText = sodium_crypto_secretbox_open($ciphertext, $nonce, $this->decodedMasterKey);
        } catch (\SodiumException $exception) {
            throw new \RuntimeException('Decryption error occurred in Libsodium.', 0, $exception);
        } finally {
            sodium_memzero($nonce);
            sodium_memzero($ciphertext);
            sodium_memzero($decoded);
        }

        if (false === $plainText) {
            throw new \RuntimeException('Decryption failed: authentication tag verification failed or key is invalid.');
        }

        return $plainText;
    }
}

<?php

declare(strict_types=1);

namespace App\Service\Security;

use SensitiveParameter;

/**
 * Contract for symmetric authenticated encryption of sensitive vault data at rest.
 */
interface EncryptionServiceInterface
{
    /**
     * Encrypts plain-text data and returns a Base64-encoded payload containing the nonce and ciphertext.
     *
     * @throws \RuntimeException If encryption fails
     */
    public function encrypt(#[SensitiveParameter] string $plainText): string;

    /**
     * Decrypts a Base64-encoded payload (nonce + ciphertext) back into plain text.
     *
     * @throws \InvalidArgumentException If the payload format is invalid or corrupted
     * @throws \RuntimeException         If authentication or decryption fails
     */
    public function decrypt(string $encryptedPayload): string;
}


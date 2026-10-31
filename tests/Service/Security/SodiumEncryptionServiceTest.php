<?php

declare(strict_types=1);

namespace App\Tests\Service\Security;

use App\Service\Security\EncryptionServiceInterface;
use App\Service\Security\SodiumEncryptionService;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class SodiumEncryptionServiceTest extends KernelTestCase
{
    public function testServiceIsAutowiredAndEncryptsAndDecryptsRoundTrip(): void
    {
        self::bootKernel();

        $encryptionService = self::getContainer()->get(EncryptionServiceInterface::class);
        self::assertInstanceOf(SodiumEncryptionService::class, $encryptionService);

        $plainText = 'super-secret-enterprise-password-!@#123';
        $encrypted = $encryptionService->encrypt($plainText);

        self::assertNotSame($plainText, $encrypted);
        self::assertSame($plainText, $encryptionService->decrypt($encrypted));
    }

    public function testEncryptProducesDifferentCiphertextsForSamePlainTextDueToRandomNonce(): void
    {
        $key = base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
        $service = new SodiumEncryptionService($key);

        $plainText = '123456';
        $firstEncrypted = $service->encrypt($plainText);
        $secondEncrypted = $service->encrypt($plainText);

        self::assertNotSame($firstEncrypted, $secondEncrypted);
        self::assertSame($plainText, $service->decrypt($firstEncrypted));
        self::assertSame($plainText, $service->decrypt($secondEncrypted));
    }

    public function testDecryptThrowsOnTamperedCiphertext(): void
    {
        $key = base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES));
        $service = new SodiumEncryptionService($key);

        $encrypted = $service->encrypt('sensitive-vault-secret');
        $decoded = base64_decode($encrypted, true);
        \assert(\is_string($decoded));

        // Flip the last byte of the authentication tag / ciphertext
        $lastIndex = \strlen($decoded) - 1;
        $decoded[$lastIndex] = \chr(\ord($decoded[$lastIndex]) ^ 0xFF);
        $tamperedPayload = base64_encode($decoded);

        $this->expectException(\RuntimeException::class);
        $service->decrypt($tamperedPayload);
    }

    public function testDecryptThrowsWithWrongKey(): void
    {
        $serviceA = new SodiumEncryptionService(base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));
        $serviceB = new SodiumEncryptionService(base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));

        $encrypted = $serviceA->encrypt('secret-data');

        $this->expectException(\RuntimeException::class);
        $serviceB->decrypt($encrypted);
    }

    public function testConstructorRejectsInvalidKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new SodiumEncryptionService(base64_encode('too-short-key'));
    }

    public function testDecryptRejectsMalformedBase64(): void
    {
        $service = new SodiumEncryptionService(base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));

        $this->expectException(\InvalidArgumentException::class);
        $service->decrypt('%%%not-valid-base64%%%');
    }

    public function testDecryptRejectsTruncatedPayload(): void
    {
        $service = new SodiumEncryptionService(base64_encode(random_bytes(\SODIUM_CRYPTO_SECRETBOX_KEYBYTES)));

        $this->expectException(\InvalidArgumentException::class);
        $service->decrypt(base64_encode('short'));
    }
}

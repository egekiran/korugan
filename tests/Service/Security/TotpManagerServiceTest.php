<?php

declare(strict_types=1);

namespace App\Tests\Service\Security;

use App\Entity\User;
use App\Service\Security\EncryptionServiceInterface;
use App\Service\Security\TotpManagerService;
use Doctrine\ORM\EntityManagerInterface;
use OTPHP\TOTP;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class TotpManagerServiceTest extends KernelTestCase
{
    private TotpAuthenticatorInterface $totpAuthenticator;
    private EncryptionServiceInterface $encryptionService;

    protected function setUp(): void
    {
        self::bootKernel();

        $container = self::getContainer();

        $totpAuthenticator = $container->get('scheb_two_factor.security.totp_authenticator');
        \assert($totpAuthenticator instanceof TotpAuthenticatorInterface);
        $this->totpAuthenticator = $totpAuthenticator;

        $encryptionService = $container->get(EncryptionServiceInterface::class);
        \assert($encryptionService instanceof EncryptionServiceInterface);
        $this->encryptionService = $encryptionService;
    }

    public function testGenerateSecretAndQrCodeContent(): void
    {
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $service = new TotpManagerService($this->totpAuthenticator, $this->encryptionService, $entityManager);

        $secret = $service->generateSecret();
        self::assertNotEmpty($secret);
        self::assertMatchesRegularExpression('/^[A-Z2-7]+$/', $secret);

        $user = new User();
        $user->setEmail('security@korugan.local');

        $qrContent = $service->getQrCodeContent($user, $secret);

        self::assertStringStartsWith('otpauth://totp/', $qrContent);
        self::assertStringContainsString('secret=' . $secret, $qrContent);
        self::assertStringContainsString('issuer=Korugan', $qrContent);
        self::assertFalse($user->isTotpAuthenticationEnabled());
    }

    public function testVerifyCodeWithOverrideSecret(): void
    {
        $entityManager = $this->createStub(EntityManagerInterface::class);
        $service = new TotpManagerService($this->totpAuthenticator, $this->encryptionService, $entityManager);

        $secret = $service->generateSecret();
        $user = new User();
        $user->setEmail('vault-admin@korugan.local');

        $validCode = TOTP::createFromSecret($secret)->now();

        self::assertTrue($service->verifyCode($user, $validCode, $secret));
        self::assertFalse($service->verifyCode($user, '000000', $secret));
    }

    public function testEnableTotpRejectsInvalidCodeAndPersistsEncryptedSecretOnValidCode(): void
    {
        $user = new User();
        $user->setEmail('enterprise@korugan.local');

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())->method('persist')->with($user);
        $entityManager->expects(self::once())->method('flush');

        $service = new TotpManagerService($this->totpAuthenticator, $this->encryptionService, $entityManager);
        $plainSecret = $service->generateSecret();

        // 1. Invalid code must not enable TOTP
        self::assertFalse($service->enableTotp($user, $plainSecret, '000000'));
        self::assertFalse($user->isTotpEnabled());
        self::assertFalse($user->isTotpAuthenticationEnabled());
        self::assertNull($user->getTotpSecret());

        // 2. Valid code must encrypt secret, enable TOTP, and flush
        $validCode = TOTP::createFromSecret($plainSecret)->now();
        self::assertTrue($service->enableTotp($user, $plainSecret, $validCode));

        self::assertTrue($user->isTotpEnabled());
        self::assertTrue($user->isTotpAuthenticationEnabled());
        self::assertNotNull($user->getTotpSecret());
        self::assertNotSame($plainSecret, $user->getTotpSecret());
        self::assertSame($plainSecret, $this->encryptionService->decrypt($user->getTotpSecret()));

        // Simulate entity loaded without transient plainTotpSecret and verify code via stored encrypted secret
        $user->setPlainTotpSecret(null);
        self::assertTrue($service->verifyCode($user, $validCode));
    }

    public function testDisableTotpClearsSecretAndDisablesAuthentication(): void
    {
        $user = new User();
        $user->setEmail('operator@korugan.local');
        $user->setTotpSecret($this->encryptionService->encrypt('JBSWY3DPEHPK3PXP'));
        $user->setPlainTotpSecret('JBSWY3DPEHPK3PXP');
        $user->setIsTotpEnabled(true);

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())->method('persist')->with($user);
        $entityManager->expects(self::once())->method('flush');

        $service = new TotpManagerService($this->totpAuthenticator, $this->encryptionService, $entityManager);
        $service->disableTotp($user);

        self::assertFalse($user->isTotpEnabled());
        self::assertFalse($user->isTotpAuthenticationEnabled());
        self::assertNull($user->getTotpSecret());
        self::assertNull($user->getPlainTotpSecret());
        self::assertNull($user->getTotpAuthenticationConfiguration());
    }
}


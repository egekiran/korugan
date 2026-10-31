<?php

declare(strict_types=1);

namespace App\Service\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use SensitiveParameter;

/**
 * Manages TOTP (Time-based One-Time Password) generation, QR provisioning URI creation,
 * verification, and encrypted persistence for two-factor authentication.
 */
final readonly class TotpManagerService
{
    public function __construct(
        private TotpAuthenticatorInterface $totpAuthenticator,
        private EncryptionServiceInterface $encryptionService,
        private EntityManagerInterface $entityManager,
    ) {
    }

    /**
     * Generates a new random Base32-encoded TOTP secret.
     */
    public function generateSecret(): string
    {
        return $this->totpAuthenticator->generateSecret();
    }

    /**
     * Builds the otpauth:// provisioning URI for Google Authenticator / TOTP apps.
     */
    public function getQrCodeContent(User $user, #[SensitiveParameter] string $plainSecret): string
    {
        $temporaryUser = clone $user;
        $temporaryUser->setPlainTotpSecret($plainSecret);

        return $this->totpAuthenticator->getQRContent($temporaryUser);
    }

    /**
     * Verifies a 6-digit TOTP code against either an override plain secret or the user's stored encrypted secret.
     */
    public function verifyCode(
        User $user,
        #[SensitiveParameter] string $code,
        #[SensitiveParameter] ?string $overrideSecret = null,
    ): bool {
        $plainSecret = $this->resolvePlainSecret($user, $overrideSecret);
        if (null === $plainSecret || '' === $plainSecret) {
            return false;
        }

        $temporaryUser = clone $user;
        $temporaryUser->setPlainTotpSecret($plainSecret);

        return $this->totpAuthenticator->checkCode($temporaryUser, $code);
    }

    /**
     * Verifies the setup code and, if valid, encrypts and persists the TOTP secret on the user.
     */
    public function enableTotp(
        User $user,
        #[SensitiveParameter] string $plainSecret,
        #[SensitiveParameter] string $code,
    ): bool {
        if (!$this->verifyCode($user, $code, $plainSecret)) {
            return false;
        }

        $encryptedSecret = $this->encryptionService->encrypt($plainSecret);

        $user->setTotpSecret($encryptedSecret);
        $user->setPlainTotpSecret($plainSecret);
        $user->setIsTotpEnabled(true);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return true;
    }

    /**
     * Disables TOTP two-factor authentication for the user and removes the stored secret.
     */
    public function disableTotp(User $user): void
    {
        $user->setIsTotpEnabled(false);
        $user->setTotpSecret(null);
        $user->setPlainTotpSecret(null);

        $this->entityManager->persist($user);
        $this->entityManager->flush();
    }

    private function resolvePlainSecret(User $user, #[SensitiveParameter] ?string $overrideSecret): ?string
    {
        if (null !== $overrideSecret) {
            return $overrideSecret;
        }

        if (null !== $user->getPlainTotpSecret() && '' !== $user->getPlainTotpSecret()) {
            return $user->getPlainTotpSecret();
        }

        $encryptedSecret = $user->getTotpSecret();
        if (null === $encryptedSecret || '' === $encryptedSecret) {
            return null;
        }

        return $this->encryptionService->decrypt($encryptedSecret);
    }
}

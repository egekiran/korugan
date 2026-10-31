<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\User;
use App\Service\Security\EncryptionServiceInterface;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsEntityListener;
use Doctrine\ORM\Event\PostLoadEventArgs;

/**
 * Automatically decrypts the User's encrypted TOTP secret into the transient plain-text property upon loading.
 */
#[AsEntityListener]
final readonly class UserEncryptionListener
{
    public function __construct(
        private EncryptionServiceInterface $encryptionService,
    ) {
    }

    public function postLoad(User $user, ?PostLoadEventArgs $event = null): void
    {
        $encryptedSecret = $user->getTotpSecret();
        if (null !== $encryptedSecret && '' !== $encryptedSecret) {
            $user->setPlainTotpSecret($this->encryptionService->decrypt($encryptedSecret));
        }
    }
}


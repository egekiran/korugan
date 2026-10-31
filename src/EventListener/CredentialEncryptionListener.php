<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\Credential;
use App\Service\Security\EncryptionServiceInterface;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsEntityListener;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;

/**
 * Automatically encrypts transient plain-text credential fields before persistence
 * and decrypts stored ciphertexts when entities are loaded from the database.
 */
#[AsEntityListener]
final readonly class CredentialEncryptionListener
{
    public function __construct(
        private EncryptionServiceInterface $encryptionService,
    ) {
    }

    public function prePersist(Credential $credential, ?PrePersistEventArgs $event = null): void
    {
        $this->encryptFields($credential);
    }

    public function preUpdate(Credential $credential, ?PreUpdateEventArgs $event = null): void
    {
        $this->encryptFields($credential);

        if (null !== $event) {
            $entityManager = $event->getObjectManager();
            $unitOfWork = $entityManager->getUnitOfWork();
            $classMetadata = $entityManager->getClassMetadata(Credential::class);

            $unitOfWork->recomputeSingleEntityChangeSet($classMetadata, $credential);
        }
    }

    public function postLoad(Credential $credential, ?PostLoadEventArgs $event = null): void
    {
        $encryptedPassword = $credential->getEncryptedPassword();
        if (null !== $encryptedPassword && '' !== $encryptedPassword) {
            $credential->setPlainPassword($this->encryptionService->decrypt($encryptedPassword));
        }

        $encryptedNotes = $credential->getEncryptedNotes();
        if (null !== $encryptedNotes && '' !== $encryptedNotes) {
            $credential->setPlainNotes($this->encryptionService->decrypt($encryptedNotes));
        }
    }

    private function encryptFields(Credential $credential): void
    {
        $plainPassword = $credential->getPlainPassword();
        if (null !== $plainPassword) {
            $credential->setEncryptedPassword($this->encryptionService->encrypt($plainPassword));
        }

        $plainNotes = $credential->getPlainNotes();
        if (null !== $plainNotes) {
            $credential->setEncryptedNotes($this->encryptionService->encrypt($plainNotes));
        }
    }
}


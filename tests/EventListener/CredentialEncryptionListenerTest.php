<?php

declare(strict_types=1);

namespace App\Tests\EventListener;

use App\Entity\Credential;
use App\EventListener\CredentialEncryptionListener;
use App\Service\Security\EncryptionServiceInterface;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Events;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

final class CredentialEncryptionListenerTest extends KernelTestCase
{
    private EncryptionServiceInterface $encryptionService;
    private CredentialEncryptionListener $listener;

    protected function setUp(): void
    {
        self::bootKernel();

        $container = self::getContainer();
        $encryptionService = $container->get(EncryptionServiceInterface::class);
        \assert($encryptionService instanceof EncryptionServiceInterface);

        $this->encryptionService = $encryptionService;
        $this->listener = new CredentialEncryptionListener($this->encryptionService);
    }

    public function testEntityMetadataRegistersCredentialEncryptionListener(): void
    {
        $entityManager = self::getContainer()->get(EntityManagerInterface::class);
        \assert($entityManager instanceof EntityManagerInterface);

        $metadata = $entityManager->getClassMetadata(Credential::class);

        self::assertArrayHasKey(Events::prePersist, $metadata->entityListeners);
        self::assertArrayHasKey(Events::preUpdate, $metadata->entityListeners);
        self::assertArrayHasKey(Events::postLoad, $metadata->entityListeners);

        self::assertSame(
            CredentialEncryptionListener::class,
            $metadata->entityListeners[Events::prePersist][0]['class'],
        );
        self::assertSame(
            CredentialEncryptionListener::class,
            $metadata->entityListeners[Events::preUpdate][0]['class'],
        );
        self::assertSame(
            CredentialEncryptionListener::class,
            $metadata->entityListeners[Events::postLoad][0]['class'],
        );
    }

    public function testPrePersistEncryptsPlainFieldsAndPostLoadRestoresPlainText(): void
    {
        $credential = new Credential(title: 'Production Redis');
        $credential->setPlainPassword('redis-master-secret-99!');
        $credential->setPlainNotes('Cluster recovery token: XYZ-987');

        self::assertNull($credential->getEncryptedPassword());
        self::assertNull($credential->getEncryptedNotes());

        // Simulate Doctrine prePersist lifecycle event
        $this->listener->prePersist($credential);

        $encryptedPassword = $credential->getEncryptedPassword();
        $encryptedNotes = $credential->getEncryptedNotes();

        self::assertNotNull($encryptedPassword);
        self::assertNotNull($encryptedNotes);
        self::assertNotSame('redis-master-secret-99!', $encryptedPassword);
        self::assertNotSame('Cluster recovery token: XYZ-987', $encryptedNotes);

        // Simulate clearing transient memory and reloading entity from database
        $credential->eraseCredentials();
        self::assertNull($credential->getPlainPassword());
        self::assertNull($credential->getPlainNotes());

        // Simulate Doctrine postLoad lifecycle event
        $this->listener->postLoad($credential);

        self::assertSame('redis-master-secret-99!', $credential->getPlainPassword());
        self::assertSame('Cluster recovery token: XYZ-987', $credential->getPlainNotes());
    }

    public function testPreUpdateReEncryptsModifiedPlainTextFields(): void
    {
        $credential = new Credential(title: 'GitLab Root');
        $credential->setPlainPassword('initial-secret');
        $credential->setPlainNotes('initial-notes');

        $this->listener->prePersist($credential);
        $initialEncryptedPassword = $credential->getEncryptedPassword();
        $initialEncryptedNotes = $credential->getEncryptedNotes();

        // Update plain-text fields and trigger preUpdate
        $credential->setPlainPassword('rotated-enterprise-secret');
        $credential->setPlainNotes('updated-recovery-notes');
        $this->listener->preUpdate($credential);

        self::assertNotSame($initialEncryptedPassword, $credential->getEncryptedPassword());
        self::assertNotSame($initialEncryptedNotes, $credential->getEncryptedNotes());

        $credential->eraseCredentials();
        $this->listener->postLoad($credential);

        self::assertSame('rotated-enterprise-secret', $credential->getPlainPassword());
        self::assertSame('updated-recovery-notes', $credential->getPlainNotes());
    }
}


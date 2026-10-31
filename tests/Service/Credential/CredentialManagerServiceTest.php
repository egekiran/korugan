<?php

declare(strict_types=1);

namespace App\Tests\Service\Credential;

use App\Dto\Credential\CreateCredentialDto;
use App\Dto\Credential\UpdateCredentialDto;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\CredentialAccessedEvent;
use App\Service\Credential\CredentialManagerService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final class CredentialManagerServiceTest extends TestCase
{
    public function testCreateCredentialPersistsEntityAndDispatchesAccessedEvent(): void
    {
        $actor = new User();
        $actor->setEmail('developer@korugan.local');

        $vault = new Vault(name: 'Dev Environment', owner: $actor);

        $dto = new CreateCredentialDto(
            title: 'Stripe Secret Key',
            plainPassword: 'sk_test_1234567890abcdef',
            username: 'api_admin',
            url: 'https://dashboard.stripe.com',
            plainNotes: 'Test mode API key with restricted permissions',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())
            ->method('persist')
            ->with(self::callback(static function (mixed $credential) use ($vault, $dto): bool {
                return $credential instanceof Credential
                    && $credential->getTitle() === $dto->title
                    && $credential->getPlainPassword() === $dto->plainPassword
                    && $credential->getUsername() === $dto->username
                    && $credential->getUrl() === $dto->url
                    && $credential->getPlainNotes() === $dto->plainNotes
                    && $credential->getVault() === $vault;
            }));
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($actor, $dto): bool {
                return $event instanceof CredentialAccessedEvent
                    && $event->getAction() === CredentialAccessedEvent::ACTION_CREATED
                    && $event->getUser() === $actor
                    && $event->getCredential()->getTitle() === $dto->title
                    && $event->getIpAddress() === '127.0.0.1'
                    && $event->getUserAgent() === 'PHPUnit/13';
            }));

        $service = new CredentialManagerService($entityManager, $eventDispatcher);
        $createdCredential = $service->createCredential($vault, $dto, $actor, '127.0.0.1', 'PHPUnit/13');

        self::assertSame('Stripe Secret Key', $createdCredential->getTitle());
        self::assertSame('sk_test_1234567890abcdef', $createdCredential->getPlainPassword());
        self::assertSame('api_admin', $createdCredential->getUsername());
        self::assertSame('https://dashboard.stripe.com', $createdCredential->getUrl());
        self::assertSame('Test mode API key with restricted permissions', $createdCredential->getPlainNotes());
        self::assertSame($vault, $createdCredential->getVault());
        self::assertCount(1, $vault->getCredentials());
    }

    public function testUpdateCredentialWithNewPasswordAndNotes(): void
    {
        $actor = new User();
        $vault = new Vault(name: 'Main Vault', owner: $actor);
        $credential = new Credential(title: 'Old Title', vault: $vault);
        $credential->setPlainPassword('old-password');
        $credential->setPlainNotes('old-notes');

        $dto = new UpdateCredentialDto(
            title: 'New Title',
            plainPassword: 'new-rotated-password',
            username: 'new-username',
            url: 'https://new-url.local',
            plainNotes: 'new-notes',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())->method('persist')->with($credential);
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($actor): bool {
                return $event instanceof CredentialAccessedEvent
                    && $event->getAction() === CredentialAccessedEvent::ACTION_UPDATED
                    && $event->getUser() === $actor
                    && $event->getCredential()->getTitle() === 'New Title';
            }));

        $service = new CredentialManagerService($entityManager, $eventDispatcher);
        $updated = $service->updateCredential($credential, $dto, $actor, '10.0.0.2', 'Agent/2.0');

        self::assertSame('New Title', $updated->getTitle());
        self::assertSame('new-rotated-password', $updated->getPlainPassword());
        self::assertSame('new-username', $updated->getUsername());
        self::assertSame('https://new-url.local', $updated->getUrl());
        self::assertSame('new-notes', $updated->getPlainNotes());
    }

    public function testUpdateCredentialRetainsExistingPasswordWhenDtoPasswordIsNull(): void
    {
        $actor = new User();
        $vault = new Vault(name: 'Main Vault', owner: $actor);
        $credential = new Credential(title: 'Server Login', vault: $vault);
        $credential->setPlainPassword('retain-this-password');
        $credential->setPlainNotes('retain-these-notes');

        $dto = new UpdateCredentialDto(
            title: 'Renamed Server Login',
            plainPassword: null,
            username: 'root_user',
            url: null,
            plainNotes: null,
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())->method('persist')->with($credential);
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event): bool {
                return $event instanceof CredentialAccessedEvent
                    && $event->getAction() === CredentialAccessedEvent::ACTION_UPDATED;
            }));

        $service = new CredentialManagerService($entityManager, $eventDispatcher);
        $updated = $service->updateCredential($credential, $dto, $actor);

        self::assertSame('Renamed Server Login', $updated->getTitle());
        self::assertSame('retain-this-password', $updated->getPlainPassword());
        self::assertSame('root_user', $updated->getUsername());
        self::assertSame('retain-these-notes', $updated->getPlainNotes());
    }

    public function testDeleteCredentialRemovesEntityAndDispatchesAccessedEvent(): void
    {
        $actor = new User();
        $vault = new Vault(name: 'Test Vault', owner: $actor);
        $credential = new Credential(title: 'To Be Deleted', vault: $vault);

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())->method('remove')->with($credential);
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($actor, $credential): bool {
                return $event instanceof CredentialAccessedEvent
                    && $event->getAction() === CredentialAccessedEvent::ACTION_DELETED
                    && $event->getUser() === $actor
                    && $event->getCredential() === $credential;
            }));

        $service = new CredentialManagerService($entityManager, $eventDispatcher);
        $service->deleteCredential($credential, $actor, '172.16.0.1', 'CLI/1.0');
    }

    public function testRevealSecretReturnsPlainPasswordAndDispatchesRevealedEvent(): void
    {
        $actor = new User();
        $vault = new Vault(name: 'Vault', owner: $actor);
        $credential = new Credential(title: 'Database Password', vault: $vault);
        $credential->setPlainPassword('high-entropy-master-pass');

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::never())->method('persist');
        $entityManager->expects(self::never())->method('remove');
        $entityManager->expects(self::never())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($actor, $credential): bool {
                return $event instanceof CredentialAccessedEvent
                    && $event->getAction() === CredentialAccessedEvent::ACTION_REVEALED
                    && $event->getUser() === $actor
                    && $event->getCredential() === $credential
                    && $event->getIpAddress() === '10.0.0.5'
                    && $event->getUserAgent() === 'VaultApp/2.1';
            }));

        $service = new CredentialManagerService($entityManager, $eventDispatcher);
        $revealed = $service->revealSecret($credential, $actor, '10.0.0.5', 'VaultApp/2.1');

        self::assertSame('high-entropy-master-pass', $revealed);
    }
}


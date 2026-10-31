<?php

declare(strict_types=1);

namespace App\Tests\Service\Vault;

use App\Dto\Vault\CreateVaultDto;
use App\Dto\Vault\UpdateVaultDto;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\VaultLifecycleEvent;
use App\Service\Vault\VaultManagerService;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

final class VaultManagerServiceTest extends TestCase
{
    public function testCreateVaultPersistsEntityAndDispatchesLifecycleEvent(): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $dto = new CreateVaultDto(
            name: 'Cloud Infrastructure Vault',
            description: 'Production cloud secrets and IAM keys',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())
            ->method('persist')
            ->with(self::callback(static function (mixed $vault) use ($owner, $dto): bool {
                return $vault instanceof Vault
                    && $vault->getName() === $dto->name
                    && $vault->getDescription() === $dto->description
                    && $vault->getOwner() === $owner;
            }));
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($owner, $dto): bool {
                return $event instanceof VaultLifecycleEvent
                    && $event->getAction() === VaultLifecycleEvent::ACTION_CREATED
                    && $event->getUser() === $owner
                    && $event->getVault()->getName() === $dto->name
                    && $event->getIpAddress() === '127.0.0.1'
                    && $event->getUserAgent() === 'PHPUnit/13';
            }));

        $service = new VaultManagerService($entityManager, $eventDispatcher);
        $createdVault = $service->createVault($owner, $dto, '127.0.0.1', 'PHPUnit/13');

        self::assertSame('Cloud Infrastructure Vault', $createdVault->getName());
        self::assertSame('Production cloud secrets and IAM keys', $createdVault->getDescription());
        self::assertSame($owner, $createdVault->getOwner());
    }

    public function testUpdateVaultModifiesFieldsAndDispatchesLifecycleEvent(): void
    {
        $owner = new User();
        $vault = new Vault(name: 'Initial Name', owner: $owner, description: 'Initial Desc');

        $dto = new UpdateVaultDto(
            name: 'Updated Vault Name',
            description: 'Updated Vault Description',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())->method('persist')->with($vault);
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($owner): bool {
                return $event instanceof VaultLifecycleEvent
                    && $event->getAction() === VaultLifecycleEvent::ACTION_UPDATED
                    && $event->getUser() === $owner
                    && $event->getVault()->getName() === 'Updated Vault Name';
            }));

        $service = new VaultManagerService($entityManager, $eventDispatcher);
        $updatedVault = $service->updateVault($vault, $dto, '10.0.0.1', 'KoruganApp/1.0');

        self::assertSame('Updated Vault Name', $updatedVault->getName());
        self::assertSame('Updated Vault Description', $updatedVault->getDescription());
    }

    public function testDeleteVaultRemovesEntityAndDispatchesLifecycleEvent(): void
    {
        $owner = new User();
        $vault = new Vault(name: 'To Delete', owner: $owner);

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('wrapInTransaction')
            ->willReturnCallback(static function (callable $operation) {
                return $operation();
            });
        $entityManager->expects(self::once())->method('remove')->with($vault);
        $entityManager->expects(self::once())->method('flush');

        $eventDispatcher = $this->createMock(EventDispatcherInterface::class);
        $eventDispatcher->expects(self::once())
            ->method('dispatch')
            ->with(self::callback(static function (mixed $event) use ($owner, $vault): bool {
                return $event instanceof VaultLifecycleEvent
                    && $event->getAction() === VaultLifecycleEvent::ACTION_DELETED
                    && $event->getUser() === $owner
                    && $event->getVault() === $vault;
            }));

        $service = new VaultManagerService($entityManager, $eventDispatcher);
        $service->deleteVault($vault, '192.168.0.5', 'Browser/5.0');
    }
}


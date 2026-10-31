<?php

declare(strict_types=1);

namespace App\Service\Vault;

use App\Dto\Vault\CreateVaultDto;
use App\Dto\Vault\UpdateVaultDto;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\VaultLifecycleEvent;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Application service managing Vault creation, updates, and deletion with domain events.
 */
final readonly class VaultManagerService
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public function createVault(
        User $owner,
        CreateVaultDto $dto,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): Vault {
        $vault = new Vault(
            name: $dto->name,
            owner: $owner,
            description: $dto->description,
        );

        $this->entityManager->wrapInTransaction(function () use ($vault): void {
            $this->entityManager->persist($vault);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new VaultLifecycleEvent(
            user: $owner,
            vault: $vault,
            action: VaultLifecycleEvent::ACTION_CREATED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        ));

        return $vault;
    }

    public function updateVault(
        Vault $vault,
        UpdateVaultDto $dto,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): Vault {
        $vault->setName($dto->name);
        $vault->setDescription($dto->description);

        $this->entityManager->wrapInTransaction(function () use ($vault): void {
            $this->entityManager->persist($vault);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new VaultLifecycleEvent(
            user: $vault->getOwner(),
            vault: $vault,
            action: VaultLifecycleEvent::ACTION_UPDATED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        ));

        return $vault;
    }

    public function deleteVault(
        Vault $vault,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): void {
        $owner = $vault->getOwner();
        $targetId = $vault->getId()?->toRfc4122();

        $this->entityManager->wrapInTransaction(function () use ($vault): void {
            $this->entityManager->remove($vault);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new VaultLifecycleEvent(
            user: $owner,
            vault: $vault,
            action: VaultLifecycleEvent::ACTION_DELETED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            targetId: $targetId,
        ));
    }
}


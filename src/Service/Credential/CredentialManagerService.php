<?php

declare(strict_types=1);

namespace App\Service\Credential;

use App\Dto\Credential\CreateCredentialDto;
use App\Dto\Credential\UpdateCredentialDto;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\CredentialAccessedEvent;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Application service managing Credential creation, updates, deletion, and secret revelation.
 */
final readonly class CredentialManagerService
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private EventDispatcherInterface $eventDispatcher,
    ) {
    }

    public function createCredential(
        Vault $vault,
        CreateCredentialDto $dto,
        User $actor,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): Credential {
        $credential = new Credential(
            title: $dto->title,
            vault: $vault,
            username: $dto->username,
            url: $dto->url,
        );
        $credential->setPlainPassword($dto->plainPassword);
        $credential->setPlainNotes($dto->plainNotes);

        $vault->addCredential($credential);

        $this->entityManager->wrapInTransaction(function () use ($credential): void {
            $this->entityManager->persist($credential);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new CredentialAccessedEvent(
            user: $actor,
            credential: $credential,
            action: CredentialAccessedEvent::ACTION_CREATED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        ));

        return $credential;
    }

    public function updateCredential(
        Credential $credential,
        UpdateCredentialDto $dto,
        User $actor,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): Credential {
        $credential->setTitle($dto->title);
        $credential->setUsername($dto->username);
        $credential->setUrl($dto->url);

        if (null !== $dto->plainPassword) {
            $credential->setPlainPassword($dto->plainPassword);
        }

        if (null !== $dto->plainNotes) {
            $credential->setPlainNotes($dto->plainNotes);
        }

        $this->entityManager->wrapInTransaction(function () use ($credential): void {
            $this->entityManager->persist($credential);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new CredentialAccessedEvent(
            user: $actor,
            credential: $credential,
            action: CredentialAccessedEvent::ACTION_UPDATED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        ));

        return $credential;
    }

    public function deleteCredential(
        Credential $credential,
        User $actor,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): void {
        $targetId = $credential->getId()?->toRfc4122();

        $this->entityManager->wrapInTransaction(function () use ($credential): void {
            $this->entityManager->remove($credential);
            $this->entityManager->flush();
        });

        $this->eventDispatcher->dispatch(new CredentialAccessedEvent(
            user: $actor,
            credential: $credential,
            action: CredentialAccessedEvent::ACTION_DELETED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
            targetId: $targetId,
        ));
    }

    public function revealSecret(
        Credential $credential,
        User $actor,
        ?string $ipAddress = null,
        ?string $userAgent = null,
    ): string {
        $plainPassword = $credential->getPlainPassword() ?? '';

        $this->eventDispatcher->dispatch(new CredentialAccessedEvent(
            user: $actor,
            credential: $credential,
            action: CredentialAccessedEvent::ACTION_REVEALED,
            ipAddress: $ipAddress,
            userAgent: $userAgent,
        ));

        return $plainPassword;
    }
}


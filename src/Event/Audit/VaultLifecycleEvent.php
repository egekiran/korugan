<?php

declare(strict_types=1);

namespace App\Event\Audit;

use App\Entity\User;
use App\Entity\Vault;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched when a Vault is created, updated, or deleted.
 */
final class VaultLifecycleEvent extends Event implements AuditEventInterface
{
    public const string TARGET_TYPE = 'Vault';

    public const string ACTION_CREATED = 'vault.created';
    public const string ACTION_UPDATED = 'vault.updated';
    public const string ACTION_DELETED = 'vault.deleted';

    private readonly ?string $targetId;

    public function __construct(
        private readonly ?User $user,
        private readonly Vault $vault,
        private readonly string $action,
        private readonly ?string $ipAddress = null,
        private readonly ?string $userAgent = null,
        ?string $targetId = null,
    ) {
        $this->targetId = $targetId ?? $this->vault->getId()?->toRfc4122();
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function getVault(): Vault
    {
        return $this->vault;
    }

    public function getAction(): string
    {
        return $this->action;
    }

    public function getTargetType(): string
    {
        return self::TARGET_TYPE;
    }

    public function getTargetId(): ?string
    {
        return $this->targetId ?? $this->vault->getId()?->toRfc4122();
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }
}


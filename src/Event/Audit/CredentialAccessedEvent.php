<?php

declare(strict_types=1);

namespace App\Event\Audit;

use App\Entity\Credential;
use App\Entity\User;
use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched whenever a Credential entity is viewed, revealed, created, updated, or deleted.
 */
final class CredentialAccessedEvent extends Event implements AuditEventInterface
{
    public const string TARGET_TYPE = 'Credential';

    public const string ACTION_REVEALED = 'credential.revealed';
    public const string ACTION_VIEWED = 'credential.viewed';
    public const string ACTION_CREATED = 'credential.created';
    public const string ACTION_UPDATED = 'credential.updated';
    public const string ACTION_DELETED = 'credential.deleted';

    private readonly ?string $targetId;

    public function __construct(
        private readonly ?User $user,
        private readonly Credential $credential,
        private readonly string $action = self::ACTION_REVEALED,
        private readonly ?string $ipAddress = null,
        private readonly ?string $userAgent = null,
        ?string $targetId = null,
    ) {
        $this->targetId = $targetId ?? $this->credential->getId()?->toRfc4122();
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function getCredential(): Credential
    {
        return $this->credential;
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
        return $this->targetId ?? $this->credential->getId()?->toRfc4122();
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


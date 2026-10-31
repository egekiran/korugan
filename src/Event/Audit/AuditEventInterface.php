<?php

declare(strict_types=1);

namespace App\Event\Audit;

use App\Entity\User;

/**
 * Contract for security audit domain events dispatched across the application.
 */
interface AuditEventInterface
{
    public function getUser(): ?User;

    public function getAction(): string;

    public function getTargetType(): string;

    public function getTargetId(): ?string;

    public function getIpAddress(): ?string;

    public function getUserAgent(): ?string;
}


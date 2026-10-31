<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\AuditLog;
use App\Event\Audit\AuditEventInterface;
use App\Event\Audit\CredentialAccessedEvent;
use App\Event\Audit\VaultLifecycleEvent;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Listens to security audit domain events and persists immutable AuditLog records in a fail-safe manner.
 */
final readonly class AuditLogSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * @return array<class-string<AuditEventInterface>, string>
     */
    public static function getSubscribedEvents(): array
    {
        return [
            CredentialAccessedEvent::class => 'onAuditEvent',
            VaultLifecycleEvent::class => 'onAuditEvent',
        ];
    }

    public function onAuditEvent(AuditEventInterface $event): void
    {
        try {
            $auditLog = new AuditLog(
                action: $event->getAction(),
                targetType: $event->getTargetType(),
                user: $event->getUser(),
                targetId: $event->getTargetId(),
                ipAddress: $event->getIpAddress(),
                userAgent: $event->getUserAgent(),
            );

            $this->entityManager->persist($auditLog);
            $this->entityManager->flush();
        } catch (\Throwable $exception) {
            $this->logger->error('Failed to persist security audit log entry.', [
                'action' => $event->getAction(),
                'target_type' => $event->getTargetType(),
                'target_id' => $event->getTargetId(),
                'user_id' => $event->getUser()?->getId(),
                'ip_address' => $event->getIpAddress(),
                'exception' => $exception->getMessage(),
            ]);
        }
    }
}


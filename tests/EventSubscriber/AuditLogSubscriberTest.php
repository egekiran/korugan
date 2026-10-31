<?php

declare(strict_types=1);

namespace App\Tests\EventSubscriber;

use App\Entity\AuditLog;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\CredentialAccessedEvent;
use App\Event\Audit\VaultLifecycleEvent;
use App\EventSubscriber\AuditLogSubscriber;
use Doctrine\ORM\EntityManagerInterface;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

final class AuditLogSubscriberTest extends TestCase
{
    public function testSubscribedEventsContainAuditEvents(): void
    {
        $events = AuditLogSubscriber::getSubscribedEvents();

        self::assertArrayHasKey(CredentialAccessedEvent::class, $events);
        self::assertArrayHasKey(VaultLifecycleEvent::class, $events);
        self::assertSame('onAuditEvent', $events[CredentialAccessedEvent::class]);
        self::assertSame('onAuditEvent', $events[VaultLifecycleEvent::class]);
    }

    public function testOnCredentialAccessedEventPersistsAuditLog(): void
    {
        $user = new User();
        $user->setEmail('auditor@korugan.local');

        $vault = new Vault(name: 'Dev Vault', owner: $user);
        $credential = new Credential(title: 'API Key', encryptedPassword: 'enc', vault: $vault);

        $event = new CredentialAccessedEvent(
            user: $user,
            credential: $credential,
            action: CredentialAccessedEvent::ACTION_REVEALED,
            ipAddress: '192.168.1.100',
            userAgent: 'Mozilla/5.0 (Korugan Agent)',
            targetId: 'custom-target-uuid-1234',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('persist')
            ->with(self::callback(function (mixed $log) use ($user): bool {
                if (!$log instanceof AuditLog) {
                    return false;
                }

                return $log->getAction() === CredentialAccessedEvent::ACTION_REVEALED
                    && $log->getTargetType() === 'Credential'
                    && $log->getUser() === $user
                    && $log->getTargetId() === 'custom-target-uuid-1234'
                    && $log->getIpAddress() === '192.168.1.100'
                    && $log->getUserAgent() === 'Mozilla/5.0 (Korugan Agent)'
                    && $log->getCreatedAt() instanceof \DateTimeImmutable;
            }));

        $entityManager->expects(self::once())->method('flush');

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');

        $subscriber = new AuditLogSubscriber($entityManager, $logger);
        $subscriber->onAuditEvent($event);
    }

    public function testOnVaultLifecycleEventPersistsAuditLog(): void
    {
        $user = new User();
        $user->setEmail('admin@korugan.local');

        $vault = new Vault(name: 'Secrets Vault', owner: $user);

        $event = new VaultLifecycleEvent(
            user: $user,
            vault: $vault,
            action: VaultLifecycleEvent::ACTION_CREATED,
            ipAddress: '2001:db8::1',
            userAgent: 'curl/8.1.0',
            targetId: 'vault-uuid-5678',
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('persist')
            ->with(self::callback(function (mixed $log) use ($user): bool {
                if (!$log instanceof AuditLog) {
                    return false;
                }

                return $log->getAction() === VaultLifecycleEvent::ACTION_CREATED
                    && $log->getTargetType() === 'Vault'
                    && $log->getUser() === $user
                    && $log->getTargetId() === 'vault-uuid-5678'
                    && $log->getIpAddress() === '2001:db8::1'
                    && $log->getUserAgent() === 'curl/8.1.0';
            }));

        $entityManager->expects(self::once())->method('flush');

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::never())->method('error');

        $subscriber = new AuditLogSubscriber($entityManager, $logger);
        $subscriber->onAuditEvent($event);
    }

    public function testFailSafeLoggingWhenPersistenceFails(): void
    {
        $user = new User();
        $vault = new Vault(name: 'Temp Vault', owner: $user);

        $event = new VaultLifecycleEvent(
            user: $user,
            vault: $vault,
            action: VaultLifecycleEvent::ACTION_DELETED,
        );

        $entityManager = $this->createMock(EntityManagerInterface::class);
        $entityManager->expects(self::once())
            ->method('persist')
            ->willThrowException(new \RuntimeException('Database connection lost'));

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects(self::once())
            ->method('error')
            ->with('Failed to persist security audit log entry.', self::callback(static fn (mixed $context): bool => \is_array($context)));

        $subscriber = new AuditLogSubscriber($entityManager, $logger);
        // Must not throw exception
        $subscriber->onAuditEvent($event);
    }
}

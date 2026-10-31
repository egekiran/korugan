<?php

declare(strict_types=1);

namespace App\Tests\Entity;

use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use PHPUnit\Framework\TestCase;

final class VaultAndCredentialTest extends TestCase
{
    public function testVaultAndCredentialRelationsAndLifecycleCallbacks(): void
    {
        $user = new User();
        $user->setEmail('architect@korugan.local');

        $vault = new Vault(
            name: 'Production Infrastructure',
            owner: $user,
            description: 'Core production server credentials',
        );
        $user->addVault($vault);

        $credential = new Credential(
            title: 'PostgreSQL Primary Cluster',
            encryptedPassword: 'base64-nonce-and-ciphertext',
            vault: $vault,
            username: 'postgres_admin',
            url: 'https://db-admin.korugan.local',
            encryptedNotes: 'base64-encrypted-notes',
        );
        $vault->addCredential($credential);

        $vault->initializeTimestamps();
        $credential->initializeTimestamps();

        self::assertCount(1, $user->getVaults());
        self::assertSame($user, $vault->getOwner());
        self::assertCount(1, $vault->getCredentials());
        self::assertSame($vault, $credential->getVault());
        self::assertSame('Production Infrastructure', $vault->getName());
        self::assertSame('PostgreSQL Primary Cluster', $credential->getTitle());
        self::assertInstanceOf(\DateTimeImmutable::class, $vault->getCreatedAt());
        self::assertInstanceOf(\DateTimeImmutable::class, $vault->getUpdatedAt());
        self::assertInstanceOf(\DateTimeImmutable::class, $credential->getCreatedAt());
        self::assertInstanceOf(\DateTimeImmutable::class, $credential->getUpdatedAt());

        $previousUpdatedAt = $credential->getUpdatedAt();
        $credential->updateTimestamp();
        self::assertGreaterThanOrEqual($previousUpdatedAt, $credential->getUpdatedAt());

        $vault->removeCredential($credential);
        self::assertCount(0, $vault->getCredentials());
        self::assertNull($credential->getVault());
    }
}


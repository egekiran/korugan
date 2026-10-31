<?php

declare(strict_types=1);

namespace App\Tests\Security\Voter;

use App\Entity\User;
use App\Entity\Vault;
use App\Security\Voter\VaultVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class VaultVoterTest extends TestCase
{
    private VaultVoter $voter;

    protected function setUp(): void
    {
        $this->voter = new VaultVoter();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function vaultAttributesProvider(): iterable
    {
        yield 'VIEW' => [VaultVoter::VIEW];
        yield 'EDIT' => [VaultVoter::EDIT];
        yield 'DELETE' => [VaultVoter::DELETE];
    }

    #[DataProvider('vaultAttributesProvider')]
    public function testVaultOwnerIsGrantedAllAttributes(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $vault = new Vault(name: 'Personal Vault', owner: $owner);
        $token = new UsernamePasswordToken($owner, 'main', $owner->getRoles());

        self::assertSame(
            VoterInterface::ACCESS_GRANTED,
            $this->voter->vote($token, $vault, [$attribute]),
        );
    }

    #[DataProvider('vaultAttributesProvider')]
    public function testDifferentUserIsDeniedAccess(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $otherUser = new User();
        $otherUser->setEmail('intruder@korugan.local');

        $vault = new Vault(name: 'Personal Vault', owner: $owner);
        $token = new UsernamePasswordToken($otherUser, 'main', $otherUser->getRoles());

        self::assertSame(
            VoterInterface::ACCESS_DENIED,
            $this->voter->vote($token, $vault, [$attribute]),
        );
    }

    #[DataProvider('vaultAttributesProvider')]
    public function testAnonymousUserIsDeniedAccess(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $vault = new Vault(name: 'Personal Vault', owner: $owner);
        $token = new NullToken();

        self::assertSame(
            VoterInterface::ACCESS_DENIED,
            $this->voter->vote($token, $vault, [$attribute]),
        );
    }

    #[DataProvider('vaultAttributesProvider')]
    public function testAdminUserIsGrantedAccessRegardlessOfOwnership(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $admin = new User();
        $admin->setEmail('admin@korugan.local');
        $admin->setRoles(['ROLE_ADMIN']);

        $vault = new Vault(name: 'Team Shared Vault', owner: $owner);
        $token = new UsernamePasswordToken($admin, 'main', $admin->getRoles());

        self::assertSame(
            VoterInterface::ACCESS_GRANTED,
            $this->voter->vote($token, $vault, [$attribute]),
        );
    }

    public function testAbstainsOnUnsupportedAttributeOrSubject(): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $vault = new Vault(name: 'Personal Vault', owner: $owner);
        $token = new UsernamePasswordToken($owner, 'main', $owner->getRoles());

        self::assertSame(
            VoterInterface::ACCESS_ABSTAIN,
            $this->voter->vote($token, $vault, ['UNSUPPORTED_ACTION']),
        );
        self::assertSame(
            VoterInterface::ACCESS_ABSTAIN,
            $this->voter->vote($token, new \stdClass(), [VaultVoter::VIEW]),
        );
    }
}


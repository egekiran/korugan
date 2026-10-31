<?php

declare(strict_types=1);

namespace App\Tests\Security\Voter;

use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Security\Voter\CredentialVoter;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Authentication\Token\NullToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

final class CredentialVoterTest extends KernelTestCase
{
    private CredentialVoter $voter;
    private TokenStorageInterface $tokenStorage;

    protected function setUp(): void
    {
        self::bootKernel();

        $container = self::getContainer();

        $security = $container->get(Security::class);
        \assert($security instanceof Security);

        $tokenStorage = $container->get('security.token_storage');
        \assert($tokenStorage instanceof TokenStorageInterface);

        $this->tokenStorage = $tokenStorage;
        $this->voter = new CredentialVoter($security);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function credentialAttributesProvider(): iterable
    {
        yield 'VIEW' => [CredentialVoter::VIEW];
        yield 'REVEAL_SECRET' => [CredentialVoter::REVEAL_SECRET];
        yield 'EDIT' => [CredentialVoter::EDIT];
        yield 'DELETE' => [CredentialVoter::DELETE];
    }

    #[DataProvider('credentialAttributesProvider')]
    public function testVaultOwnerIsGrantedAllCredentialAttributes(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $vault = new Vault(name: 'Engineering Vault', owner: $owner);
        $credential = new Credential(title: 'AWS Root Account', encryptedPassword: 'enc', vault: $vault);

        $token = new UsernamePasswordToken($owner, 'main', $owner->getRoles());
        $this->tokenStorage->setToken($token);

        self::assertSame(
            VoterInterface::ACCESS_GRANTED,
            $this->voter->vote($token, $credential, [$attribute]),
        );
    }

    #[DataProvider('credentialAttributesProvider')]
    public function testDifferentUserIsDeniedCredentialAccess(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $otherUser = new User();
        $otherUser->setEmail('outsider@korugan.local');

        $vault = new Vault(name: 'Engineering Vault', owner: $owner);
        $credential = new Credential(title: 'AWS Root Account', encryptedPassword: 'enc', vault: $vault);

        $token = new UsernamePasswordToken($otherUser, 'main', $otherUser->getRoles());
        $this->tokenStorage->setToken($token);

        self::assertSame(
            VoterInterface::ACCESS_DENIED,
            $this->voter->vote($token, $credential, [$attribute]),
        );
    }

    #[DataProvider('credentialAttributesProvider')]
    public function testAnonymousUserIsDeniedCredentialAccess(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $vault = new Vault(name: 'Engineering Vault', owner: $owner);
        $credential = new Credential(title: 'AWS Root Account', encryptedPassword: 'enc', vault: $vault);

        $token = new NullToken();
        $this->tokenStorage->setToken($token);

        self::assertSame(
            VoterInterface::ACCESS_DENIED,
            $this->voter->vote($token, $credential, [$attribute]),
        );
    }

    #[DataProvider('credentialAttributesProvider')]
    public function testAdminUserIsGrantedAllCredentialAttributes(string $attribute): void
    {
        $owner = new User();
        $owner->setEmail('owner@korugan.local');

        $admin = new User();
        $admin->setEmail('admin@korugan.local');
        $admin->setRoles(['ROLE_ADMIN']);

        $vault = new Vault(name: 'Engineering Vault', owner: $owner);
        $credential = new Credential(title: 'AWS Root Account', encryptedPassword: 'enc', vault: $vault);

        $token = new UsernamePasswordToken($admin, 'main', $admin->getRoles());
        $this->tokenStorage->setToken($token);

        self::assertSame(
            VoterInterface::ACCESS_GRANTED,
            $this->voter->vote($token, $credential, [$attribute]),
        );
    }
}


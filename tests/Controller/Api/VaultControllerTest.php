<?php

declare(strict_types=1);

namespace App\Tests\Controller\Api;

use App\Entity\User;
use App\Entity\Vault;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

final class VaultControllerTest extends WebTestCase
{
    private KernelBrowser $client;
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->entityManager = static::getContainer()->get(EntityManagerInterface::class);
    }

    public function testUnauthenticatedRequestsReturn401(): void
    {
        $this->client->request('GET', '/api/vaults');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $this->client->request('POST', '/api/vaults', [], [], ['CONTENT_TYPE' => 'application/json'], '{"name":"Test"}');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testCreateAndListVaults(): void
    {
        $user = $this->createTestUser('vault_owner_' . uniqid() . '@korugan.local');
        $this->client->loginUser($user);

        // 1. Create a vault
        $payload = json_encode([
            'name' => 'Backend Infrastructure',
            'description' => 'Credentials for production AWS, GCP, and Cloudflare',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/vaults', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_USER_AGENT' => 'Korugan-API-Test',
        ], $payload);

        self::assertResponseStatusCodeSame(Response::HTTP_CREATED);
        $createData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('id', $createData);
        self::assertSame('Backend Infrastructure', $createData['name']);
        self::assertSame('Credentials for production AWS, GCP, and Cloudflare', $createData['description']);

        // 2. List vaults
        $this->client->request('GET', '/api/vaults');
        self::assertResponseIsSuccessful();
        $listData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($listData);
        self::assertNotEmpty($listData);
        self::assertSame('Backend Infrastructure', $listData[0]['name']);
    }

    public function testShowUpdateAndDeleteVault(): void
    {
        $owner = $this->createTestUser('owner_' . uniqid() . '@korugan.local');
        $vault = new Vault(name: 'Initial Vault', owner: $owner, description: 'Initial Desc');
        $this->entityManager->persist($vault);
        $this->entityManager->flush();

        $this->client->loginUser($owner);
        $vaultId = $vault->getId()?->toRfc4122();

        // 1. Show vault
        $this->client->request('GET', '/api/vaults/' . $vaultId);
        self::assertResponseIsSuccessful();
        $showData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Initial Vault', $showData['name']);
        self::assertArrayHasKey('credentials', $showData);

        // 2. Update vault
        $updatePayload = json_encode([
            'name' => 'Updated Vault Name',
            'description' => 'Updated Vault Description',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('PUT', '/api/vaults/' . $vaultId, [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $updatePayload);

        self::assertResponseIsSuccessful();
        $updateData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Updated Vault Name', $updateData['name']);
        self::assertSame('Updated Vault Description', $updateData['description']);

        // 3. Delete vault
        $this->client->request('DELETE', '/api/vaults/' . $vaultId);
        self::assertResponseStatusCodeSame(Response::HTTP_NO_CONTENT);

        // Verify entity is removed
        $this->entityManager->clear();
        $deletedVault = $this->entityManager->find(Vault::class, $vaultId);
        self::assertNull($deletedVault);
    }

    public function testAccessDeniedForOtherUsersVault(): void
    {
        $owner = $this->createTestUser('vault_owner_' . uniqid() . '@korugan.local');
        $intruder = $this->createTestUser('intruder_' . uniqid() . '@korugan.local');

        $vault = new Vault(name: 'Private Vault', owner: $owner);
        $this->entityManager->persist($vault);
        $this->entityManager->flush();

        $vaultId = $vault->getId()?->toRfc4122();

        $this->client->loginUser($intruder);

        // Show someone else's vault -> 403 Forbidden
        $this->client->request('GET', '/api/vaults/' . $vaultId);
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Update someone else's vault -> 403 Forbidden
        $this->client->request('PUT', '/api/vaults/' . $vaultId, [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"name":"Hacked Name"}');
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Delete someone else's vault -> 403 Forbidden
        $this->client->request('DELETE', '/api/vaults/' . $vaultId);
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);
    }

    private function createTestUser(string $email): User
    {
        $user = new User();
        $user->setEmail($email);
        $user->setPassword('dummy_hashed_password');

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }
}


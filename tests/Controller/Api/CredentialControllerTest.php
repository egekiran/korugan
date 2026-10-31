<?php

declare(strict_types=1);

namespace App\Tests\Controller\Api;

use App\Entity\AuditLog;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Event\Audit\CredentialAccessedEvent;
use App\Repository\AuditLogRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

final class CredentialControllerTest extends WebTestCase
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
        $this->client->request('GET', '/api/credentials/018f0000-0000-7000-0000-000000000000');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $this->client->request('POST', '/api/credentials/018f0000-0000-7000-0000-000000000000/reveal');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testCreateShowUpdateDeleteAndRevealCredentialLifecycle(): void
    {
        $owner = $this->createTestUser('cred_owner_' . uniqid() . '@korugan.local');
        $vault = new Vault(name: 'Production Vault', owner: $owner);
        $this->entityManager->persist($vault);
        $this->entityManager->flush();

        $vaultId = $vault->getId()?->toRfc4122();
        $this->client->loginUser($owner);

        // 1. Create Credential
        $createPayload = json_encode([
            'title' => 'PostgreSQL Cluster Master',
            'username' => 'pg_master_admin',
            'plainPassword' => 'p@ssw0rd-Super-Secret-2026',
            'url' => 'https://db-cluster.internal',
            'plainNotes' => 'Superuser credentials for migration execution',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/vaults/' . $vaultId . '/credentials', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_USER_AGENT' => 'Korugan-Credential-Test/1.0',
        ], $createPayload);

        self::assertResponseStatusCodeSame(Response::HTTP_CREATED);
        $createData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('id', $createData);
        self::assertSame('PostgreSQL Cluster Master', $createData['title']);
        self::assertSame('pg_master_admin', $createData['username']);
        self::assertSame('https://db-cluster.internal', $createData['url']);
        // Verify plain secrets or ciphertexts are NOT leaked in response
        self::assertArrayNotHasKey('plainPassword', $createData);
        self::assertArrayNotHasKey('encryptedPassword', $createData);
        self::assertArrayNotHasKey('plainNotes', $createData);
        self::assertArrayNotHasKey('encryptedNotes', $createData);

        $credentialId = $createData['id'];

        // 2. Show Credential metadata
        $this->client->request('GET', '/api/credentials/' . $credentialId);
        self::assertResponseIsSuccessful();
        $showData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('PostgreSQL Cluster Master', $showData['title']);
        self::assertArrayNotHasKey('plainPassword', $showData);
        self::assertArrayNotHasKey('encryptedPassword', $showData);

        // 3. Update Credential
        $updatePayload = json_encode([
            'title' => 'PostgreSQL Cluster Primary (Rotated)',
            'username' => 'pg_master_v2',
            'plainPassword' => 'new-rotated-secret-2026!',
            'url' => 'https://db-primary.internal',
            'plainNotes' => 'Rotated on schedule',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('PUT', '/api/credentials/' . $credentialId, [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $updatePayload);

        self::assertResponseIsSuccessful();
        $updateData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('PostgreSQL Cluster Primary (Rotated)', $updateData['title']);
        self::assertSame('pg_master_v2', $updateData['username']);

        // 4. Reveal Secret
        $this->client->request('POST', '/api/credentials/' . $credentialId . '/reveal', [], [], [
            'HTTP_USER_AGENT' => 'AuditAgent/1.0',
        ]);
        self::assertResponseIsSuccessful();
        $revealData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('plainPassword', $revealData);
        self::assertSame('new-rotated-secret-2026!', $revealData['plainPassword']);

        // 5. Verify AuditLog entry was persisted in the database for 'credential.revealed'
        $auditLogRepo = static::getContainer()->get(AuditLogRepository::class);
        $logs = $auditLogRepo->findBy([
            'action' => CredentialAccessedEvent::ACTION_REVEALED,
            'targetId' => $credentialId,
        ]);

        self::assertNotEmpty($logs, 'An audit log entry for credential.revealed should be recorded.');
        /** @var AuditLog $log */
        $log = $logs[0];
        self::assertSame('Credential', $log->getTargetType());
        self::assertSame($owner->getId(), $log->getUser()?->getId());
        self::assertSame('AuditAgent/1.0', $log->getUserAgent());

        // 6. Delete Credential
        $this->client->request('DELETE', '/api/credentials/' . $credentialId);
        self::assertResponseStatusCodeSame(Response::HTTP_NO_CONTENT);

        // Verify entity is removed
        $this->entityManager->clear();
        $deleted = $this->entityManager->find(Credential::class, $credentialId);
        self::assertNull($deleted);
    }

    public function testAccessDeniedForOtherUsersCredential(): void
    {
        $owner = $this->createTestUser('owner_sec_' . uniqid() . '@korugan.local');
        $intruder = $this->createTestUser('intruder_sec_' . uniqid() . '@korugan.local');

        $vault = new Vault(name: 'Private Vault', owner: $owner);
        $credential = new Credential(title: 'Top Secret Token', vault: $vault);
        $credential->setPlainPassword('super-secret-token');
        $vault->addCredential($credential);

        $this->entityManager->persist($vault);
        $this->entityManager->flush();

        $vaultId = $vault->getId()?->toRfc4122();
        $credentialId = $credential->getId()?->toRfc4122();

        $this->client->loginUser($intruder);

        // Attempt to create credential in someone else's vault -> 403 Forbidden
        $this->client->request('POST', '/api/vaults/' . $vaultId . '/credentials', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"title":"Malicious","plainPassword":"test"}');
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Attempt to view someone else's credential -> 403 Forbidden
        $this->client->request('GET', '/api/credentials/' . $credentialId);
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Attempt to update someone else's credential -> 403 Forbidden
        $this->client->request('PUT', '/api/credentials/' . $credentialId, [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"title":"Hacked"}');
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Attempt to delete someone else's credential -> 403 Forbidden
        $this->client->request('DELETE', '/api/credentials/' . $credentialId);
        self::assertResponseStatusCodeSame(Response::HTTP_FORBIDDEN);

        // Attempt to reveal someone else's credential -> 403 Forbidden
        $this->client->request('POST', '/api/credentials/' . $credentialId . '/reveal');
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


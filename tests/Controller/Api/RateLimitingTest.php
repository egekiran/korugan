<?php

declare(strict_types=1);

namespace App\Tests\Controller\Api;

use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

final class RateLimitingTest extends WebTestCase
{
    private KernelBrowser $client;
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->entityManager = static::getContainer()->get(EntityManagerInterface::class);

        if (static::getContainer()->has('cache.rate_limiter')) {
            static::getContainer()->get('cache.rate_limiter')->clear();
        }
    }

    public function testAuthRateLimiterBlocksAfterFiveRequests(): void
    {
        $fixedClientIp = '198.51.' . random_int(1, 200) . '.' . random_int(1, 254);

        // 1. Send 5 requests from the same IP -> must be accepted by limiter (not 429)
        for ($i = 1; $i <= 5; ++$i) {
            $payload = json_encode([
                'email' => 'ratelimit_user_' . $i . '_' . uniqid() . '@korugan.local',
                'password' => 'SecurePass123!',
            ], \JSON_THROW_ON_ERROR);

            $this->client->request('POST', '/api/auth/register', [], [], [
                'CONTENT_TYPE' => 'application/json',
                'REMOTE_ADDR' => $fixedClientIp,
            ], $payload);

            self::assertResponseStatusCodeSame(Response::HTTP_CREATED);
        }

        // 2. The 6th request from the same IP must be rejected with 429 Too Many Requests
        $payloadSixth = json_encode([
            'email' => 'ratelimit_user_overflow@korugan.local',
            'password' => 'SecurePass123!',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/auth/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
            'REMOTE_ADDR' => $fixedClientIp,
        ], $payloadSixth);

        self::assertResponseStatusCodeSame(Response::HTTP_TOO_MANY_REQUESTS);
        self::assertTrue($this->client->getResponse()->headers->has('Retry-After'));

        $responseData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Too many requests. Please try again later.', $responseData['error']);
    }

    public function testRevealSecretRateLimiterBlocksAfterTenRequests(): void
    {
        $owner = new User();
        $owner->setEmail('rate_limit_owner_' . uniqid() . '@korugan.local');
        $owner->setPassword('dummy_hash');

        $vault = new Vault(name: 'Rate Limiter Vault', owner: $owner);
        $credential = new Credential(title: 'High Security Token', vault: $vault);
        $credential->setPlainPassword('ultra-sensitive-master-key');
        $vault->addCredential($credential);

        $this->entityManager->persist($owner);
        $this->entityManager->persist($vault);
        $this->entityManager->flush();

        $credentialId = $credential->getId()?->toRfc4122();
        $this->client->loginUser($owner);

        // 1. Consume 10 allowed tokens in 1 minute
        for ($i = 1; $i <= 10; ++$i) {
            $this->client->request('POST', '/api/credentials/' . $credentialId . '/reveal');
            self::assertResponseIsSuccessful();
        }

        // 2. The 11th request must be rejected with 429 Too Many Requests
        $this->client->request('POST', '/api/credentials/' . $credentialId . '/reveal');

        self::assertResponseStatusCodeSame(Response::HTTP_TOO_MANY_REQUESTS);
        self::assertTrue($this->client->getResponse()->headers->has('Retry-After'));

        $responseData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Too many requests. Please try again later.', $responseData['error']);
    }
}

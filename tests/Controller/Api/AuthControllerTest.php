<?php

declare(strict_types=1);

namespace App\Tests\Controller\Api;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use OTPHP\TOTP;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

final class AuthControllerTest extends WebTestCase
{
    private KernelBrowser $client;
    private EntityManagerInterface $entityManager;

    protected function setUp(): void
    {
        $this->client = static::createClient();
        $this->entityManager = static::getContainer()->get(EntityManagerInterface::class);
    }

    public function testRegisterUserSuccessfullyAndRejectsDuplicateEmail(): void
    {
        $uniqueEmail = 'new_user_' . uniqid() . '@korugan.local';

        $payload = json_encode([
            'email' => $uniqueEmail,
            'password' => 'SecurePassw0rd!2026',
        ], \JSON_THROW_ON_ERROR);

        // 1. Successful registration -> 201 Created
        $this->client->request('POST', '/api/auth/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        self::assertResponseStatusCodeSame(Response::HTTP_CREATED);
        $data = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('id', $data);
        self::assertSame($uniqueEmail, $data['email']);

        // 2. Duplicate registration attempt -> 409 Conflict
        $this->client->request('POST', '/api/auth/register', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $payload);

        self::assertResponseStatusCodeSame(Response::HTTP_CONFLICT);
        $conflictData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('error', $conflictData);
    }

    public function testUnauthenticatedUserCannotAccess2faEndpoints(): void
    {
        $this->client->request('POST', '/api/auth/2fa/setup');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $this->client->request('POST', '/api/auth/2fa/enable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"secret":"ABC","code":"123456"}');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);

        $this->client->request('POST', '/api/auth/2fa/disable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], '{"code":"123456"}');
        self::assertResponseStatusCodeSame(Response::HTTP_UNAUTHORIZED);
    }

    public function testTwoFactorAuthenticationLifecycle(): void
    {
        $user = new User();
        $user->setEmail('totp_tester_' . uniqid() . '@korugan.local');
        $user->setPassword('dummy_pass');

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        $this->client->loginUser($user);

        // 1. Setup 2FA
        $this->client->request('POST', '/api/auth/2fa/setup');
        self::assertResponseIsSuccessful();
        $setupData = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);

        self::assertArrayHasKey('secret', $setupData);
        self::assertArrayHasKey('qrCodeContent', $setupData);
        self::assertStringStartsWith('otpauth://totp/', $setupData['qrCodeContent']);

        $secret = $setupData['secret'];

        // 2. Try to enable with invalid code -> 400 Bad Request
        $invalidPayload = json_encode([
            'secret' => $secret,
            'code' => '000000',
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/auth/2fa/enable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $invalidPayload);

        self::assertResponseStatusCodeSame(Response::HTTP_BAD_REQUEST);

        // 3. Enable with valid TOTP code -> 200 OK
        $validCode = TOTP::createFromSecret($secret)->now();
        $validPayload = json_encode([
            'secret' => $secret,
            'code' => $validCode,
        ], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/auth/2fa/enable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $validPayload);

        self::assertResponseIsSuccessful();
        $enableResponse = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Two-factor authentication successfully enabled.', $enableResponse['message']);

        // Refresh entity from DB to verify 2FA status
        $this->entityManager->clear();
        $refreshedUser = $this->entityManager->find(User::class, $user->getId());
        \assert($refreshedUser instanceof User);
        self::assertTrue($refreshedUser->isTotpEnabled());
        self::assertTrue($refreshedUser->isTotpAuthenticationEnabled());

        // Re-login refreshed user
        $this->client->loginUser($refreshedUser);

        // 4. Try to disable with invalid code -> 400 Bad Request
        $invalidDisablePayload = json_encode(['code' => '000000'], \JSON_THROW_ON_ERROR);
        $this->client->request('POST', '/api/auth/2fa/disable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $invalidDisablePayload);

        self::assertResponseStatusCodeSame(Response::HTTP_BAD_REQUEST);

        // 5. Disable with valid TOTP code -> 200 OK
        $validDisableCode = TOTP::createFromSecret($secret)->now();
        $validDisablePayload = json_encode(['code' => $validDisableCode], \JSON_THROW_ON_ERROR);

        $this->client->request('POST', '/api/auth/2fa/disable', [], [], [
            'CONTENT_TYPE' => 'application/json',
        ], $validDisablePayload);

        self::assertResponseIsSuccessful();
        $disableResponse = json_decode((string) $this->client->getResponse()->getContent(), true, 512, \JSON_THROW_ON_ERROR);
        self::assertSame('Two-factor authentication successfully disabled.', $disableResponse['message']);

        // Verify entity state in DB after disable
        $this->entityManager->clear();
        $disabledUser = $this->entityManager->find(User::class, $user->getId());
        \assert($disabledUser instanceof User);
        self::assertFalse($disabledUser->isTotpEnabled());
        self::assertFalse($disabledUser->isTotpAuthenticationEnabled());
        self::assertNull($disabledUser->getTotpSecret());
    }
}


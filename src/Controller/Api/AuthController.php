<?php

declare(strict_types=1);

namespace App\Controller\Api;

use App\Dto\Auth\EnableTotpRequestDto;
use App\Dto\Auth\RegisterRequestDto;
use App\Dto\Auth\VerifyTotpRequestDto;
use App\Entity\User;
use App\Repository\UserRepository;
use App\Service\Security\TotpManagerService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * REST API controller handling user registration and TOTP two-factor authentication lifecycle.
 */
#[Route('/api/auth', name: 'api_auth_')]
final class AuthController extends AbstractController
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly TotpManagerService $totpManagerService,
        private readonly RateLimiterFactory $authLimiter,
    ) {
    }

    #[Route('/register', name: 'register', methods: ['POST'])]
    public function register(
        #[MapRequestPayload] RegisterRequestDto $dto,
        Request $request,
    ): JsonResponse {
        $rateLimitResponse = $this->checkRateLimit($request->getClientIp());
        if (null !== $rateLimitResponse) {
            return $rateLimitResponse;
        }

        $normalizedEmail = mb_strtolower(trim($dto->email));

        if (null !== $this->userRepository->findOneBy(['email' => $normalizedEmail])) {
            return $this->json(
                ['error' => 'User with this email already exists.'],
                Response::HTTP_CONFLICT,
            );
        }

        $user = new User();
        $user->setEmail($normalizedEmail);
        $user->setPassword($this->passwordHasher->hashPassword($user, $dto->password));
        $user->setRoles(['ROLE_USER']);

        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $this->json([
            'id' => $user->getId(),
            'email' => $user->getEmail(),
        ], Response::HTTP_CREATED);
    }

    #[Route('/2fa/setup', name: '2fa_setup', methods: ['POST'])]
    #[IsGranted('ROLE_USER')]
    public function setup2fa(#[CurrentUser] User $user): JsonResponse
    {
        $secret = $this->totpManagerService->generateSecret();
        $qrCodeContent = $this->totpManagerService->getQrCodeContent($user, $secret);

        return $this->json([
            'secret' => $secret,
            'qrCodeContent' => $qrCodeContent,
        ], Response::HTTP_OK);
    }

    #[Route('/2fa/enable', name: '2fa_enable', methods: ['POST'])]
    #[IsGranted('ROLE_USER')]
    public function enable2fa(
        #[CurrentUser] User $user,
        #[MapRequestPayload] EnableTotpRequestDto $dto,
        Request $request,
    ): JsonResponse {
        $rateLimitResponse = $this->checkRateLimit($request->getClientIp());
        if (null !== $rateLimitResponse) {
            return $rateLimitResponse;
        }

        $enabled = $this->totpManagerService->enableTotp($user, $dto->secret, $dto->code);

        if (!$enabled) {
            return $this->json(
                ['error' => 'Invalid verification code.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        return $this->json(
            ['message' => 'Two-factor authentication successfully enabled.'],
            Response::HTTP_OK,
        );
    }

    #[Route('/2fa/disable', name: '2fa_disable', methods: ['POST'])]
    #[IsGranted('ROLE_USER')]
    public function disable2fa(
        #[CurrentUser] User $user,
        #[MapRequestPayload] VerifyTotpRequestDto $dto,
        Request $request,
    ): JsonResponse {
        $rateLimitResponse = $this->checkRateLimit($request->getClientIp());
        if (null !== $rateLimitResponse) {
            return $rateLimitResponse;
        }

        if (!$user->isTotpEnabled() || !$this->totpManagerService->verifyCode($user, $dto->code)) {
            return $this->json(
                ['error' => 'Invalid verification code.'],
                Response::HTTP_BAD_REQUEST,
            );
        }

        $this->totpManagerService->disableTotp($user);

        return $this->json(
            ['message' => 'Two-factor authentication successfully disabled.'],
            Response::HTTP_OK,
        );
    }

    private function checkRateLimit(?string $clientIp): ?JsonResponse
    {
        $limiter = $this->authLimiter->create($clientIp ?? '127.0.0.1');
        $limit = $limiter->consume();

        if (!$limit->isAccepted()) {
            $retryAfterSeconds = max(1, $limit->getRetryAfter()->getTimestamp() - time());

            return $this->json(
                ['error' => 'Too many requests. Please try again later.'],
                Response::HTTP_TOO_MANY_REQUESTS,
                ['Retry-After' => (string) $retryAfterSeconds],
            );
        }

        return null;
    }
}

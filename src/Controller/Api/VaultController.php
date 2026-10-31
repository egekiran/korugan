<?php

declare(strict_types=1);

namespace App\Controller\Api;

use App\Dto\Vault\CreateVaultDto;
use App\Dto\Vault\UpdateVaultDto;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Repository\VaultRepository;
use App\Security\Voter\VaultVoter;
use App\Service\Vault\VaultManagerService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * REST API controller managing vault resources.
 */
#[Route('/api/vaults', name: 'api_vaults_')]
#[IsGranted('ROLE_USER')]
final class VaultController extends AbstractController
{
    public function __construct(
        private readonly VaultManagerService $vaultManagerService,
        private readonly VaultRepository $vaultRepository,
    ) {
    }

    #[Route('', name: 'list', methods: ['GET'])]
    public function list(#[CurrentUser] User $user): JsonResponse
    {
        $vaults = $this->vaultRepository->findBy(['owner' => $user], ['createdAt' => 'DESC']);

        $data = array_map(
            fn (Vault $vault): array => $this->serializeVaultSummary($vault),
            $vaults,
        );

        return $this->json($data, Response::HTTP_OK);
    }

    #[Route('', name: 'create', methods: ['POST'])]
    public function create(
        #[MapRequestPayload] CreateVaultDto $dto,
        #[CurrentUser] User $user,
        Request $request,
    ): JsonResponse {
        $vault = $this->vaultManagerService->createVault(
            owner: $user,
            dto: $dto,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return $this->json($this->serializeVaultSummary($vault), Response::HTTP_CREATED);
    }

    #[Route('/{id}', name: 'show', methods: ['GET'])]
    public function show(Vault $vault): JsonResponse
    {
        $this->denyAccessUnlessGranted(VaultVoter::VIEW, $vault);

        $credentialSummaries = array_map(
            fn (Credential $credential): array => [
                'id' => $credential->getId()?->toRfc4122(),
                'title' => $credential->getTitle(),
                'username' => $credential->getUsername(),
                'url' => $credential->getUrl(),
                'createdAt' => $credential->getCreatedAt()?->format(\DateTimeInterface::ATOM),
                'updatedAt' => $credential->getUpdatedAt()?->format(\DateTimeInterface::ATOM),
            ],
            $vault->getCredentials()->toArray(),
        );

        $data = [
            'id' => $vault->getId()?->toRfc4122(),
            'name' => $vault->getName(),
            'description' => $vault->getDescription(),
            'createdAt' => $vault->getCreatedAt()?->format(\DateTimeInterface::ATOM),
            'updatedAt' => $vault->getUpdatedAt()?->format(\DateTimeInterface::ATOM),
            'credentials' => $credentialSummaries,
        ];

        return $this->json($data, Response::HTTP_OK);
    }

    #[Route('/{id}', name: 'update', methods: ['PUT'])]
    public function update(
        Vault $vault,
        #[MapRequestPayload] UpdateVaultDto $dto,
        Request $request,
    ): JsonResponse {
        $this->denyAccessUnlessGranted(VaultVoter::EDIT, $vault);

        $updatedVault = $this->vaultManagerService->updateVault(
            vault: $vault,
            dto: $dto,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return $this->json($this->serializeVaultSummary($updatedVault), Response::HTTP_OK);
    }

    #[Route('/{id}', name: 'delete', methods: ['DELETE'])]
    public function delete(Vault $vault, Request $request): JsonResponse
    {
        $this->denyAccessUnlessGranted(VaultVoter::DELETE, $vault);

        $this->vaultManagerService->deleteVault(
            vault: $vault,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return new JsonResponse(null, Response::HTTP_NO_CONTENT);
    }

    /**
     * @return array{id: ?string, name: ?string, description: ?string, createdAt: ?string, updatedAt: ?string}
     */
    private function serializeVaultSummary(Vault $vault): array
    {
        return [
            'id' => $vault->getId()?->toRfc4122(),
            'name' => $vault->getName(),
            'description' => $vault->getDescription(),
            'createdAt' => $vault->getCreatedAt()?->format(\DateTimeInterface::ATOM),
            'updatedAt' => $vault->getUpdatedAt()?->format(\DateTimeInterface::ATOM),
        ];
    }
}


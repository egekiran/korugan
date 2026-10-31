<?php

declare(strict_types=1);

namespace App\Controller\Api;

use App\Dto\Credential\CreateCredentialDto;
use App\Dto\Credential\UpdateCredentialDto;
use App\Entity\Credential;
use App\Entity\User;
use App\Entity\Vault;
use App\Security\Voter\CredentialVoter;
use App\Security\Voter\VaultVoter;
use App\Service\Credential\CredentialManagerService;
use Symfony\Bridge\Doctrine\Attribute\MapEntity;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Attribute\MapRequestPayload;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * REST API controller managing credential secrets and metadata.
 */
#[Route('/api', name: 'api_credentials_')]
#[IsGranted('ROLE_USER')]
final class CredentialController extends AbstractController
{
    public function __construct(
        private readonly CredentialManagerService $credentialManagerService,
    ) {
    }

    #[Route('/vaults/{vaultId}/credentials', name: 'create', methods: ['POST'])]
    public function create(
        #[MapEntity(id: 'vaultId')] Vault $vault,
        #[MapRequestPayload] CreateCredentialDto $dto,
        #[CurrentUser] User $user,
        Request $request,
    ): JsonResponse {
        $this->denyAccessUnlessGranted(VaultVoter::EDIT, $vault);

        $credential = $this->credentialManagerService->createCredential(
            vault: $vault,
            dto: $dto,
            actor: $user,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return $this->json($this->serializeMetadata($credential), Response::HTTP_CREATED);
    }

    #[Route('/credentials/{id}', name: 'show', methods: ['GET'])]
    public function show(Credential $credential): JsonResponse
    {
        $this->denyAccessUnlessGranted(CredentialVoter::VIEW, $credential);

        return $this->json($this->serializeMetadata($credential), Response::HTTP_OK);
    }

    #[Route('/credentials/{id}', name: 'update', methods: ['PUT'])]
    public function update(
        Credential $credential,
        #[MapRequestPayload] UpdateCredentialDto $dto,
        #[CurrentUser] User $user,
        Request $request,
    ): JsonResponse {
        $this->denyAccessUnlessGranted(CredentialVoter::EDIT, $credential);

        $updatedCredential = $this->credentialManagerService->updateCredential(
            credential: $credential,
            dto: $dto,
            actor: $user,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return $this->json($this->serializeMetadata($updatedCredential), Response::HTTP_OK);
    }

    #[Route('/credentials/{id}', name: 'delete', methods: ['DELETE'])]
    public function delete(
        Credential $credential,
        #[CurrentUser] User $user,
        Request $request,
    ): JsonResponse {
        $this->denyAccessUnlessGranted(CredentialVoter::DELETE, $credential);

        $this->credentialManagerService->deleteCredential(
            credential: $credential,
            actor: $user,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return new JsonResponse(null, Response::HTTP_NO_CONTENT);
    }

    #[Route('/credentials/{id}/reveal', name: 'reveal', methods: ['POST'])]
    public function reveal(
        Credential $credential,
        #[CurrentUser] User $user,
        Request $request,
    ): JsonResponse {
        $this->denyAccessUnlessGranted(CredentialVoter::REVEAL_SECRET, $credential);

        $plainPassword = $this->credentialManagerService->revealSecret(
            credential: $credential,
            actor: $user,
            ipAddress: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
        );

        return $this->json(['plainPassword' => $plainPassword], Response::HTTP_OK);
    }

    /**
     * @return array{id: ?string, title: ?string, username: ?string, url: ?string, createdAt: ?string, updatedAt: ?string}
     */
    private function serializeMetadata(Credential $credential): array
    {
        return [
            'id' => $credential->getId()?->toRfc4122(),
            'title' => $credential->getTitle(),
            'username' => $credential->getUsername(),
            'url' => $credential->getUrl(),
            'createdAt' => $credential->getCreatedAt()?->format(\DateTimeInterface::ATOM),
            'updatedAt' => $credential->getUpdatedAt()?->format(\DateTimeInterface::ATOM),
        ];
    }
}


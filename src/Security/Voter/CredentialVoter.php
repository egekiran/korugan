<?php

declare(strict_types=1);

namespace App\Security\Voter;

use App\Entity\Credential;
use App\Entity\User;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Enforces object-level access control on Credential entities by delegating authorization to the parent Vault.
 *
 * @extends Voter<string, Credential>
 */
final class CredentialVoter extends Voter
{
    public const string VIEW = 'CREDENTIAL_VIEW';
    public const string REVEAL_SECRET = 'CREDENTIAL_REVEAL_SECRET';
    public const string EDIT = 'CREDENTIAL_EDIT';
    public const string DELETE = 'CREDENTIAL_DELETE';

    private const array SUPPORTED_ATTRIBUTES = [
        self::VIEW,
        self::REVEAL_SECRET,
        self::EDIT,
        self::DELETE,
    ];

    public function __construct(
        private readonly Security $security,
    ) {
    }

    public function supportsAttribute(string $attribute): bool
    {
        return \in_array($attribute, self::SUPPORTED_ATTRIBUTES, true);
    }

    public function supportsType(string $subjectType): bool
    {
        return is_a($subjectType, Credential::class, true);
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $this->supportsAttribute($attribute) && $subject instanceof Credential;
    }

    protected function voteOnAttribute(
        string $attribute,
        mixed $subject,
        TokenInterface $token,
        ?Vote $vote = null,
    ): bool {
        $user = $token->getUser();

        if (!$user instanceof User) {
            return false;
        }

        $vault = $subject->getVault();
        if (null === $vault) {
            return false;
        }

        return match ($attribute) {
            self::VIEW, self::REVEAL_SECRET => $this->security->isGranted(VaultVoter::VIEW, $vault),
            self::EDIT => $this->security->isGranted(VaultVoter::EDIT, $vault),
            self::DELETE => $this->security->isGranted(VaultVoter::DELETE, $vault),
            default => false,
        };
    }
}


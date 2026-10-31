<?php

declare(strict_types=1);

namespace App\Security\Voter;

use App\Entity\User;
use App\Entity\Vault;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * Enforces object-level access control on Vault entities.
 *
 * @extends Voter<string, Vault>
 */
final class VaultVoter extends Voter
{
    public const string VIEW = 'VAULT_VIEW';
    public const string EDIT = 'VAULT_EDIT';
    public const string DELETE = 'VAULT_DELETE';

    private const array SUPPORTED_ATTRIBUTES = [
        self::VIEW,
        self::EDIT,
        self::DELETE,
    ];

    public function supportsAttribute(string $attribute): bool
    {
        return \in_array($attribute, self::SUPPORTED_ATTRIBUTES, true);
    }

    public function supportsType(string $subjectType): bool
    {
        return is_a($subjectType, Vault::class, true);
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $this->supportsAttribute($attribute) && $subject instanceof Vault;
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

        if (\in_array('ROLE_ADMIN', $token->getRoleNames(), true) || \in_array('ROLE_ADMIN', $user->getRoles(), true)) {
            return true;
        }

        return match ($attribute) {
            self::VIEW, self::EDIT, self::DELETE => $subject->getOwner() === $user,
            default => false,
        };
    }
}


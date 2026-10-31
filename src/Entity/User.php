<?php

declare(strict_types=1);

namespace App\Entity;

use App\EventListener\UserEncryptionListener;
use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Scheb\TwoFactorBundle\Model\Totp\TotpConfiguration;
use Scheb\TwoFactorBundle\Model\Totp\TotpConfigurationInterface;
use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface;
use SensitiveParameter;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\EntityListeners([UserEncryptionListener::class])]
#[ORM\Table(name: '`user`')]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
class User implements UserInterface, PasswordAuthenticatedUserInterface, TwoFactorInterface
{
    public const string TOTP_ISSUER = 'Korugan';
    public const int TOTP_PERIOD = 30;
    public const int TOTP_DIGITS = 6;

    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    private ?string $email = null;

    /**
     * @var list<string> The user roles
     */
    #[ORM\Column]
    private array $roles = [];

    /**
     * @var string|null The hashed password
     */
    #[ORM\Column]
    private ?string $password = null;

    /**
     * Base64-encoded encrypted TOTP secret stored at rest.
     */
    #[ORM\Column(type: Types::STRING, length: 255, nullable: true)]
    private ?string $totpSecret = null;

    /**
     * Transient plain-text Base32 TOTP secret (never persisted to the database).
     */
    private ?string $plainTotpSecret = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => false])]
    private bool $isTotpEnabled = false;

    /**
     * @var Collection<int, Vault>
     */
    #[ORM\OneToMany(
        targetEntity: Vault::class,
        mappedBy: 'owner',
        cascade: ['persist', 'remove'],
        orphanRemoval: true,
    )]
    private Collection $vaults;

    public function __construct()
    {
        $this->vaults = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    /**
     * A visual identifier that represents this user.
     *
     * @see UserInterface
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_values(array_unique($roles));
    }

    /**
     * @param list<string> $roles
     */
    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    /**
     * @see PasswordAuthenticatedUserInterface
     */
    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(#[SensitiveParameter] string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function getTotpSecret(): ?string
    {
        return $this->totpSecret;
    }

    public function setTotpSecret(#[SensitiveParameter] ?string $totpSecret): static
    {
        $this->totpSecret = $totpSecret;

        return $this;
    }

    public function getPlainTotpSecret(): ?string
    {
        return $this->plainTotpSecret;
    }

    public function setPlainTotpSecret(#[SensitiveParameter] ?string $plainTotpSecret): static
    {
        $this->plainTotpSecret = $plainTotpSecret;

        return $this;
    }

    public function isTotpEnabled(): bool
    {
        return $this->isTotpEnabled;
    }

    public function setIsTotpEnabled(bool $isTotpEnabled): static
    {
        $this->isTotpEnabled = $isTotpEnabled;

        return $this;
    }

    public function isTotpAuthenticationEnabled(): bool
    {
        return $this->isTotpEnabled && null !== $this->totpSecret;
    }

    public function getTotpAuthenticationUsername(): string
    {
        return (string) $this->email;
    }

    public function getTotpAuthenticationConfiguration(): ?TotpConfigurationInterface
    {
        $secret = $this->plainTotpSecret ?? $this->totpSecret;
        if (null === $secret || '' === $secret) {
            return null;
        }

        return new TotpConfiguration(
            $secret,
            TotpConfiguration::ALGORITHM_SHA1,
            self::TOTP_PERIOD,
            self::TOTP_DIGITS,
        );
    }

    /**
     * @return Collection<int, Vault>
     */
    public function getVaults(): Collection
    {
        return $this->vaults;
    }

    public function addVault(Vault $vault): static
    {
        if (!$this->vaults->contains($vault)) {
            $this->vaults->add($vault);
            $vault->setOwner($this);
        }

        return $this;
    }

    public function removeVault(Vault $vault): static
    {
        if ($this->vaults->removeElement($vault)) {
            if ($vault->getOwner() === $this) {
                $vault->setOwner(null);
            }
        }

        return $this;
    }

    /**
     * Ensure the session doesn't contain actual password hashes or plain TOTP secrets.
     */
    public function __serialize(): array
    {
        $data = (array) $this;
        $data["\0" . self::class . "\0password"] = hash('crc32c', (string) $this->password);
        unset($data["\0" . self::class . "\0plainTotpSecret"]);

        return $data;
    }
}

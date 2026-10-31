<?php

declare(strict_types=1);

namespace App\Entity;

use App\EventListener\CredentialEncryptionListener;
use App\Repository\CredentialRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use SensitiveParameter;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Represents an encrypted credential entry stored inside a Vault.
 */
#[ORM\Entity(repositoryClass: CredentialRepository::class)]
#[ORM\EntityListeners([CredentialEncryptionListener::class])]
#[ORM\Table(name: 'credential')]
#[ORM\Index(name: 'idx_credential_vault', columns: ['vault_id'])]
#[ORM\HasLifecycleCallbacks]
class Credential
{
    #[ORM\Id]
    #[ORM\Column(type: UuidType::NAME, unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $updatedAt = null;

    /**
     * Transient plain-text password (never persisted directly to the database).
     */
    private ?string $plainPassword = null;

    /**
     * Transient plain-text notes (never persisted directly to the database).
     */
    private ?string $plainNotes = null;

    public function __construct(
        #[ORM\Column(type: Types::STRING, length: 200)]
        private ?string $title = null,
        /**
         * Base64-encoded ciphertext (nonce + encrypted password).
         */
        #[ORM\Column(type: Types::TEXT)]
        #[SensitiveParameter]
        private ?string $encryptedPassword = null,
        #[ORM\ManyToOne(targetEntity: Vault::class, inversedBy: 'credentials')]
        #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
        private ?Vault $vault = null,
        #[ORM\Column(type: Types::STRING, length: 255, nullable: true)]
        private ?string $username = null,
        #[ORM\Column(type: Types::STRING, length: 2048, nullable: true)]
        private ?string $url = null,
        /**
         * Base64-encoded ciphertext (nonce + encrypted notes).
         */
        #[ORM\Column(type: Types::TEXT, nullable: true)]
        #[SensitiveParameter]
        private ?string $encryptedNotes = null,
    ) {
    }

    #[ORM\PrePersist]
    public function initializeTimestamps(): void
    {
        $now = new \DateTimeImmutable();
        $this->createdAt ??= $now;
        $this->updatedAt = $now;
    }

    #[ORM\PreUpdate]
    public function updateTimestamp(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
    }

    public function getId(): ?Uuid
    {
        return $this->id;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function setTitle(string $title): static
    {
        $this->title = $title;

        return $this;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(?string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function getEncryptedPassword(): ?string
    {
        return $this->encryptedPassword;
    }

    public function setEncryptedPassword(#[SensitiveParameter] string $encryptedPassword): static
    {
        $this->encryptedPassword = $encryptedPassword;

        return $this;
    }

    public function getPlainPassword(): ?string
    {
        return $this->plainPassword;
    }

    public function setPlainPassword(#[SensitiveParameter] ?string $plainPassword): static
    {
        if (null !== $this->id && null !== $this->plainPassword && $this->plainPassword !== $plainPassword) {
            $this->updatedAt = new \DateTimeImmutable();
        }

        $this->plainPassword = $plainPassword;

        return $this;
    }

    public function getUrl(): ?string
    {
        return $this->url;
    }

    public function setUrl(?string $url): static
    {
        $this->url = $url;

        return $this;
    }

    public function getEncryptedNotes(): ?string
    {
        return $this->encryptedNotes;
    }

    public function setEncryptedNotes(#[SensitiveParameter] ?string $encryptedNotes): static
    {
        $this->encryptedNotes = $encryptedNotes;

        return $this;
    }

    public function getPlainNotes(): ?string
    {
        return $this->plainNotes;
    }

    public function setPlainNotes(#[SensitiveParameter] ?string $plainNotes): static
    {
        if (null !== $this->id && $this->plainNotes !== $plainNotes) {
            $this->updatedAt = new \DateTimeImmutable();
        }

        $this->plainNotes = $plainNotes;

        return $this;
    }

    /**
     * Clears transient plain-text sensitive data from memory.
     */
    public function eraseCredentials(): void
    {
        $this->plainPassword = null;
        $this->plainNotes = null;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }

    public function setUpdatedAt(\DateTimeImmutable $updatedAt): static
    {
        $this->updatedAt = $updatedAt;

        return $this;
    }

    public function getVault(): ?Vault
    {
        return $this->vault;
    }

    public function setVault(?Vault $vault): static
    {
        $this->vault = $vault;

        return $this;
    }
}

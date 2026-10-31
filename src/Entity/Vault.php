<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\VaultRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Types\UuidType;
use Symfony\Component\Uid\Uuid;

/**
 * Represents a secure vault container owned by a user for storing encrypted credentials.
 */
#[ORM\Entity(repositoryClass: VaultRepository::class)]
#[ORM\Table(name: 'vault')]
#[ORM\Index(name: 'idx_vault_owner', columns: ['owner_id'])]
#[ORM\HasLifecycleCallbacks]
class Vault
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
     * @var Collection<int, Credential>
     */
    #[ORM\OneToMany(
        targetEntity: Credential::class,
        mappedBy: 'vault',
        cascade: ['persist', 'remove'],
        orphanRemoval: true,
    )]
    private Collection $credentials;

    public function __construct(
        #[ORM\Column(type: Types::STRING, length: 150)]
        private ?string $name = null,
        #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'vaults')]
        #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
        private ?User $owner = null,
        #[ORM\Column(type: Types::TEXT, nullable: true)]
        private ?string $description = null,
    ) {
        $this->credentials = new ArrayCollection();
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

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;

        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): static
    {
        $this->description = $description;

        return $this;
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

    public function getOwner(): ?User
    {
        return $this->owner;
    }

    public function setOwner(?User $owner): static
    {
        $this->owner = $owner;

        return $this;
    }

    /**
     * @return Collection<int, Credential>
     */
    public function getCredentials(): Collection
    {
        return $this->credentials;
    }

    public function addCredential(Credential $credential): static
    {
        if (!$this->credentials->contains($credential)) {
            $this->credentials->add($credential);
            $credential->setVault($this);
        }

        return $this;
    }

    public function removeCredential(Credential $credential): static
    {
        if ($this->credentials->removeElement($credential)) {
            if ($credential->getVault() === $this) {
                $credential->setVault(null);
            }
        }

        return $this;
    }
}


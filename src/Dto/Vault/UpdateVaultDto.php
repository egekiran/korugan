<?php

declare(strict_types=1);

namespace App\Dto\Vault;

use Symfony\Component\Validator\Constraints as Assert;

final readonly class UpdateVaultDto
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Length(max: 150)]
        public string $name,
        #[Assert\Length(max: 1000)]
        public ?string $description = null,
    ) {
    }
}


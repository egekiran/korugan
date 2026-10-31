<?php

declare(strict_types=1);

namespace App\Dto\Credential;

use SensitiveParameter;
use Symfony\Component\Validator\Constraints as Assert;

final readonly class UpdateCredentialDto
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Length(max: 200)]
        public string $title,
        #[SensitiveParameter]
        public ?string $plainPassword = null,
        #[Assert\Length(max: 255)]
        public ?string $username = null,
        #[Assert\Url]
        #[Assert\Length(max: 2048)]
        public ?string $url = null,
        #[SensitiveParameter]
        public ?string $plainNotes = null,
    ) {
    }
}


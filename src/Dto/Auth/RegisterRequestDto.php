<?php

declare(strict_types=1);

namespace App\Dto\Auth;

use SensitiveParameter;
use Symfony\Component\Validator\Constraints as Assert;

final readonly class RegisterRequestDto
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Email]
        public string $email,
        #[Assert\NotBlank]
        #[Assert\Length(min: 8, max: 128)]
        #[SensitiveParameter]
        public string $password,
    ) {
    }
}


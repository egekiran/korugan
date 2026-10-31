<?php

declare(strict_types=1);

namespace App\Dto\Auth;

use SensitiveParameter;
use Symfony\Component\Validator\Constraints as Assert;

final readonly class VerifyTotpRequestDto
{
    public function __construct(
        #[Assert\NotBlank]
        #[Assert\Length(min: 6, max: 6)]
        #[SensitiveParameter]
        public string $code,
    ) {
    }
}


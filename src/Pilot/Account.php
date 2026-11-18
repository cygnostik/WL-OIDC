<?php
declare(strict_types=1);

namespace PdOidc\Pilot;

final readonly class Account
{
    public function __construct(
        public string $subject,
        public string $email,
        public string $name,
        public bool $enabled,
        public bool $emailVerified,
        public int $sessionVersion,
    ) {}
}

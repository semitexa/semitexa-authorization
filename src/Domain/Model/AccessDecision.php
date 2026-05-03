<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Authorization\Domain\Enum\DenyReason;

final readonly class AccessDecision
{
    public function __construct(
        public bool $allowed,
        public ?DenyReason $denyReason = null,
        public string $message = '',
    ) {}

    public static function allow(): self
    {
        return new self(allowed: true);
    }

    public static function denyAuthRequired(string $message = 'Authentication required'): self
    {
        return new self(
            allowed: false,
            denyReason: DenyReason::AuthenticationRequired,
            message: $message,
        );
    }

    public static function denyForbidden(DenyReason $reason, string $message = 'Access denied'): self
    {
        return new self(
            allowed: false,
            denyReason: $reason,
            message: $message,
        );
    }

    public static function denyInvalidMetadata(string $message): self
    {
        return new self(
            allowed: false,
            denyReason: DenyReason::InvalidPolicyMetadata,
            message: $message,
        );
    }
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Resolved access policy for a specific payload.
 *
 * Holds the merged authorization metadata from the full payload class hierarchy.
 */
final readonly class AccessPolicy
{
    /**
     * @param list<CapabilityInterface> $requiredCapabilities
     * @param list<string>     $requiredPermissions
     */
    public function __construct(
        public bool $isPublic,
        public array $requiredCapabilities,
        public array $requiredPermissions,
    ) {}
}

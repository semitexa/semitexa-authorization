<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Policy;

use Semitexa\Authorization\Capability\Capability;

interface PayloadAccessPolicyResolverInterface
{
    public function isPublic(object $payload): bool;

    /** @return list<Capability> */
    public function requiredCapabilities(object $payload): array;

    /** @return list<string> */
    public function requiredPermissions(object $payload): array;

    /**
     * Validates the merged authorization metadata for the given payload.
     *
     * Throws \InvalidArgumentException for invalid combinations such as:
     *   - #[PublicEndpoint] + #[RequiresPermission]
     *   - #[PublicEndpoint] + #[RequiresCapability]
     *   even when the conflict spans the class hierarchy.
     *
     * This check is a boot-time invariant and must never be deferred to first-request time.
     */
    public function assertValidMetadata(object $payload): void;
}

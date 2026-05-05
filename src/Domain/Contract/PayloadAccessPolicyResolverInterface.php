<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Contract;

use Semitexa\Core\Auth\PayloadAccessType;

interface PayloadAccessPolicyResolverInterface
{
    public function isPublic(object $payload): bool;

    /** @return list<CapabilityInterface> */
    public function requiredCapabilities(object $payload): array;

    /** @return list<string> */
    public function requiredPermissions(object $payload): array;

    /**
     * The single explicit access classification of $payload — set by exactly
     * one of #[AsPublicPayload], #[AsProtectedPayload], or #[AsServicePayload].
     *
     * Throws \InvalidArgumentException when the payload has zero or more than
     * one access attribute (the resolver enforces fail-loud at call time).
     */
    public function accessType(object $payload): PayloadAccessType;

    /**
     * Validates the merged authorization metadata for the given payload.
     *
     * Throws \InvalidArgumentException when:
     *   - the payload declares no payload-access attribute
     *   - the payload declares more than one access attribute
     *   - #[AsPublicPayload]  is combined with #[RequiresCapability]/#[RequiresPermission]
     *   - #[AsServicePayload] is combined with #[RequiresCapability]/#[RequiresPermission]
     * Conflicts are detected across the full class hierarchy.
     *
     * This is a boot-time invariant and must never be deferred to first-request time.
     */
    public function assertValidMetadata(object $payload): void;
}

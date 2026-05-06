<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;
use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

// #[RequiresCapability] only applies to #[AsProtectedPayload]; combining it
// with #[AsPublicPayload] or #[AsServicePayload] is rejected at boot by
// PayloadAccessPolicyResolver::assertValidMetadata.

/**
 * Requires the authenticated subject to hold a specific capability.
 *
 * Capabilities are coarse-grained, code-level, and evaluated at request time
 * against the subject's grant set. Multiple #[RequiresCapability] declarations
 * on the same payload are combined with logical AND — the subject must satisfy
 * every declared capability.
 *
 * CapabilityInterface checks run before slug-based permission checks.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class RequiresCapability
{
    public function __construct(public CapabilityInterface $capability) {}
}

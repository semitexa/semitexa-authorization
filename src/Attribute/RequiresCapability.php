<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;
use Semitexa\Authorization\Capability\Capability;

/**
 * Requires the authenticated subject to hold a specific capability.
 *
 * Capabilities are coarse-grained, code-level, and evaluated at request time
 * against the subject's grant set. Multiple #[RequiresCapability] declarations
 * on the same payload are combined with logical AND — the subject must satisfy
 * every declared capability.
 *
 * Capability checks run before slug-based permission checks.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class RequiresCapability
{
    public function __construct(public Capability $capability) {}
}

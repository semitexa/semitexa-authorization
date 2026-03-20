<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attributes;

use Attribute;

/**
 * Requires the authenticated subject to hold a specific slug-based permission.
 *
 * Slug-based permissions are fine-grained, business-specific, and configurable.
 * Multiple #[RequiresPermission] declarations on the same payload are combined
 * with logical AND — the subject must satisfy every declared permission.
 *
 * Permission checks run after capability checks.
 *
 * #[RequiresPermission] always implies an authenticated user must exist.
 * It must not be combined with #[PublicEndpoint].
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class RequiresPermission
{
    public function __construct(public string $permission) {}
}

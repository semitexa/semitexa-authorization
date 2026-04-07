<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;

/**
 * Marks a payload class as explicitly public.
 *
 * By default every payload requires authentication. Adding #[PublicEndpoint]
 * opts the endpoint into anonymous access. This must be intentional and visible
 * in code — the absence of this attribute is what keeps endpoints protected.
 *
 * Invalid combinations (caught at boot-time):
 *   - #[PublicEndpoint] + #[RequiresCapability] on the same payload (or across class hierarchy)
 *   - #[PublicEndpoint] + #[RequiresPermission] on the same payload (or across class hierarchy)
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class PublicEndpoint
{
}

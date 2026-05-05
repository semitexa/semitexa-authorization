<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Auth\PayloadAccessType;

/**
 * Marks a payload as user-facing protected — requires user/session/admin/
 * customer authentication. May be combined with #[RequiresCapability] and
 * #[RequiresPermission] for fine-grained authorization.
 *
 * For machine-to-machine endpoints (webhook receivers, partner APIs, signed
 * integrations) declare #[AsServicePayload] instead. Service is a separate
 * access class, not a flavor of protected.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class AsProtectedPayload extends AbstractPayloadRoute
{
    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Protected;
    }
}

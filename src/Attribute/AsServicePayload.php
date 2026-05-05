<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Attribute;

use Attribute;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Auth\PayloadAccessType;

/**
 * Marks a payload as machine-to-machine: signed webhook receivers, machine
 * tokens, partner APIs, deployment callbacks, NATS/HTTP bridges, internal
 * service calls. The endpoint is authenticated by service-level credentials
 * — bearer machine token, signed body, mTLS, etc. — NOT by a user session.
 *
 * MUST NOT be combined with #[RequiresCapability] or #[RequiresPermission];
 * those attributes target user-facing protected endpoints. Service-payload
 * authorization is enforced by the service-auth handler chain (e.g. the
 * MachineAuthHandler in semitexa-api), not by user grant sets.
 *
 * Distinct from #[AsPublicPayload]: a publicly reachable URL that requires
 * a signature is a service payload, not a public one.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class AsServicePayload extends AbstractPayloadRoute
{
    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Service;
    }
}

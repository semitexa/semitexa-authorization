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
 * The service-auth handler chain (e.g. MachineAuthHandler in semitexa-api)
 * establishes the service principal. To restrict WHICH services may call the
 * route, add #[RequiresCapability]: it is checked against the service's grants
 * through ServiceCapabilityProviderInterface. #[RequiresPermission] MUST NOT
 * be combined with it — permissions are user-domain only — and the pairing is
 * refused (PayloadAccessPolicyResolver::assertValidMetadata).
 *
 * Distinct from #[AsPublicPayload]: a publicly reachable URL that requires
 * a signature is a service payload, not a public one.
 *
 * @api
 */
#[Attribute(Attribute::TARGET_CLASS)]
final class AsServicePayload extends AbstractPayloadRoute
{
    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Service;
    }
}

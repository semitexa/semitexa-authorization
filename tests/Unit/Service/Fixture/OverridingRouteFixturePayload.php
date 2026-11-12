<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

use Semitexa\Authorization\Attribute\AsProtectedPayload;

/** A route override: it extends the route and redeclares its attribute, as RouteOverrideChain requires. */
#[AsProtectedPayload(path: '/fixture/landing', methods: ['GET'], overrides: OverriddenRouteFixturePayload::class)]
final class OverridingRouteFixturePayload extends OverriddenRouteFixturePayload
{
}

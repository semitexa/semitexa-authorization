<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

/** A screen whose route attribute carries its permission. */
#[PermissionRouteFixture(permission: 'users')]
class ScreenRouteFixturePayload
{
}

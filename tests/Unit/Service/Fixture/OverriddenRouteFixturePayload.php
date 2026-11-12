<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

use Semitexa\Authorization\Attribute\AsProtectedPayload;
use Semitexa\Authorization\Attribute\RequiresPermission;

/** The route a project overrides: protected, with a permission of its own. */
#[AsProtectedPayload(path: '/fixture/landing', methods: ['GET'])]
#[RequiresPermission('landing.read')]
class OverriddenRouteFixturePayload
{
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

use Semitexa\Authorization\Attribute\AsProtectedPayload;

/** Overrides the screen's route with a plain protected attribute that states no permission. */
#[AsProtectedPayload(path: '/fixture/screen', methods: ['GET'], overrides: ScreenRouteFixturePayload::class)]
final class OverridingScreenFixturePayload extends ScreenRouteFixturePayload
{
}

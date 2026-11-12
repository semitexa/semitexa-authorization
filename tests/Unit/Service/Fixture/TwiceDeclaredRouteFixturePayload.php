<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

use Semitexa\Authorization\Attribute\AsProtectedPayload;
use Semitexa\Core\Attribute\AsPublicPayload;

/** One class, two access attributes: still refused. */
#[AsPublicPayload(path: '/fixture/twice', methods: ['GET'])]
#[AsProtectedPayload(path: '/fixture/twice', methods: ['GET'])]
final class TwiceDeclaredRouteFixturePayload extends OverriddenRouteFixturePayload
{
}

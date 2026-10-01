<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Pipeline;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * The capability AuthorizationListenerWithoutAuthorizerTest guards a fixture
 * payload with.
 *
 * Its own file, not declared inside the test: #[RequiresCapability] takes an
 * enum case, which can only be read by code that can load the enum, and a
 * class declared in the middle of a test file is loadable only by running that
 * file. The project graph could not read the attribute while it lived there.
 */
enum FixtureCapability: string implements CapabilityInterface
{
    case Dangerous = 'fixture.dangerous';
}

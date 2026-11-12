<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Application\Service\PayloadAccessPolicyResolver;
use Semitexa\Authorization\Tests\Unit\Service\Fixture\InheritingRouteFixturePayload;
use Semitexa\Authorization\Tests\Unit\Service\Fixture\InheritingScreenFixturePayload;
use Semitexa\Authorization\Tests\Unit\Service\Fixture\OverridingScreenFixturePayload;
use Semitexa\Authorization\Tests\Unit\Service\Fixture\OverridingRouteFixturePayload;
use Semitexa\Authorization\Tests\Unit\Service\Fixture\TwiceDeclaredRouteFixturePayload;
use Semitexa\Core\Auth\PayloadAccessType;

/**
 * A route override's access is read from the override (tk-route-override-chain-access).
 * RouteOverrideChain requires the child to redeclare its route attribute, and
 * the resolver counted the parent's as a second one: on 2026-11-11 a payload
 * extending HelloPayload with `overrides: HelloPayload::class` won the route in
 * discovery and answered every request with a 500, "declares multiple
 * payload-access attributes".
 */
final class RouteOverrideAccessTest extends TestCase
{
    /** @var array<class-string, mixed> The resolver's process-wide cache as the test found it. */
    private array $cache = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->cache = (new \ReflectionProperty(PayloadAccessPolicyResolver::class, 'cache'))->getValue();
        PayloadAccessPolicyResolver::clearCache();
    }

    protected function tearDown(): void
    {
        (new \ReflectionProperty(PayloadAccessPolicyResolver::class, 'cache'))->setValue(null, $this->cache);
        parent::tearDown();
    }

    #[Test]
    public function an_override_is_resolved_by_its_own_attribute(): void
    {
        $resolver = new PayloadAccessPolicyResolver();
        $override = new OverridingRouteFixturePayload();

        $resolver->assertValidMetadata($override);
        self::assertSame(PayloadAccessType::Protected, $resolver->accessType($override));
        // What the overridden route asked for still applies: an override cannot drop a requirement by accident.
        self::assertSame(['landing.read'], $resolver->requiredPermissions($override));
    }

    /** Fable review: the permission a parent's route attribute states itself was dropped by the override. */
    #[Test]
    public function an_override_keeps_the_permission_its_parents_route_attribute_states(): void
    {
        $resolver = new PayloadAccessPolicyResolver();
        $override = new OverridingScreenFixturePayload();

        self::assertSame(PayloadAccessType::Protected, $resolver->accessType($override));
        // Asked about the class the attribute sits on, the screen, not the override (review, authorization#34).
        self::assertSame(['users.read', 'declared-on:ScreenRouteFixturePayload'], $resolver->requiredPermissions($override));
    }

    #[Test]
    public function a_subclass_without_its_own_attribute_keeps_its_parents(): void
    {
        $resolver = new PayloadAccessPolicyResolver();

        self::assertSame(PayloadAccessType::Protected, $resolver->accessType(new InheritingRouteFixturePayload()));
        self::assertSame(['landing.read'], $resolver->requiredPermissions(new InheritingRouteFixturePayload()));
        // The inherited attribute is asked about the class it sits on, not the subclass.
        self::assertSame(['users.read', 'declared-on:ScreenRouteFixturePayload'], $resolver->requiredPermissions(new InheritingScreenFixturePayload()));
    }

    #[Test]
    public function one_class_with_two_access_attributes_is_still_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('declares multiple payload-access attributes');

        (new PayloadAccessPolicyResolver())->accessType(new TwiceDeclaredRouteFixturePayload());
    }
}

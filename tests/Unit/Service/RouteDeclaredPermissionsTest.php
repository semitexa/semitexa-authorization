<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service;

use Attribute;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Application\Service\PayloadAccessPolicyResolver;
use Semitexa\Authorization\Attribute\RequiresPermission;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Auth\PayloadAccessType;
use Semitexa\Core\Contract\DeclaresRequiredPermissionsInterface;

/**
 * A route attribute that states its own permissions (a CRUD screen's
 * `{permission}.read`) adds them to the policy, beside any
 * #[RequiresPermission] — the screen needs no hand-written guard.
 */
final class RouteDeclaredPermissionsTest extends TestCase
{
    protected function tearDown(): void
    {
        PayloadAccessPolicyResolver::clearCache();
    }

    #[Test]
    public function the_route_attributes_permissions_join_the_declared_ones(): void
    {
        $resolver = new PayloadAccessPolicyResolver();

        self::assertSame(['content.read'], $resolver->requiredPermissions(new RouteGuardedFixturePayload()));
        self::assertSame(['audit.view', 'content.read'], $resolver->requiredPermissions(new RouteAndAttributeGuardedFixturePayload()));
        self::assertSame(PayloadAccessType::Protected, $resolver->accessType(new RouteGuardedFixturePayload()));
    }
}

#[Attribute(Attribute::TARGET_CLASS)]
final class GuardedRouteFixture extends AbstractPayloadRoute implements DeclaresRequiredPermissionsInterface
{
    public function __construct(public readonly string $permission)
    {
        parent::__construct(path: '/fixture/guarded', methods: ['GET']);
    }

    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Protected;
    }

    public function requiredPermissions(string $payloadClass): array
    {
        return [$this->permission . '.read'];
    }
}

#[GuardedRouteFixture(permission: 'content')]
final class RouteGuardedFixturePayload
{
}

#[GuardedRouteFixture(permission: 'content')]
#[RequiresPermission('audit.view')]
#[RequiresPermission('content.read')]
final class RouteAndAttributeGuardedFixturePayload
{
}

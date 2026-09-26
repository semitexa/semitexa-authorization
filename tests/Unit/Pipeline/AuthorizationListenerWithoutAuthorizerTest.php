<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Pipeline;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Attribute\AsProtectedPayload;
use Semitexa\Authorization\Attribute\RequiresCapability;
use Semitexa\Authorization\Attribute\RequiresPermission;
use Semitexa\Authorization\Domain\Contract\CapabilityInterface;
use Semitexa\Authorization\Domain\Enum\DenyReason;
use Semitexa\Authorization\Domain\Event\AuthorizationDenied;
use Semitexa\Authorization\Pipeline\AuthorizationListener;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Discovery\DiscoveredRoute;
use Semitexa\Core\Event\EventDispatcherInterface;
use Semitexa\Core\Exception\AccessDeniedException;
use Semitexa\Core\Pipeline\RequestPipelineContext;
use Semitexa\Core\Request;

/**
 * With no authorizer registered nothing can evaluate a permission, so a route
 * that declares one must be refused — not quietly reduced to "signed in".
 */
final class AuthorizationListenerWithoutAuthorizerTest extends TestCase
{
    #[Test]
    public function a_permission_route_is_denied_when_nothing_can_evaluate_the_permission(): void
    {
        $this->expectException(AccessDeniedException::class);

        (new AuthorizationListener())->handle($this->context(new PermissionGuardedFixturePayload()));
    }

    #[Test]
    public function a_capability_route_is_denied_when_nothing_can_evaluate_the_capability(): void
    {
        $this->expectException(AccessDeniedException::class);

        (new AuthorizationListener())->handle($this->context(new CapabilityGuardedFixturePayload()));
    }

    #[Test]
    public function the_fallback_denial_is_audited_like_any_other(): void
    {
        $listener = new AuthorizationListener();
        $events = new class implements EventDispatcherInterface {
            /** @var list<object> */
            public array $dispatched = [];

            public function create(string $eventClass, array $payload): object
            {
                throw new \LogicException('not used');
            }

            public function dispatch(object $event): void
            {
                $this->dispatched[] = $event;
            }

            public function addPostDispatchHook(callable $hook): void
            {
            }
        };
        (new \ReflectionProperty(AuthorizationListener::class, 'events'))->setValue($listener, $events);

        try {
            $listener->handle($this->context(new CapabilityGuardedFixturePayload()));
            self::fail('the capability route must be denied');
        } catch (AccessDeniedException) {
        }

        self::assertCount(1, $events->dispatched);
        $event = $events->dispatched[0];
        self::assertInstanceOf(AuthorizationDenied::class, $event);
        self::assertSame(DenyReason::CapabilityRequired, $event->decision->denyReason);
        self::assertSame(CapabilityGuardedFixturePayload::class, $event->payloadClass);
    }

    #[Test]
    public function a_plain_protected_route_still_admits_a_signed_in_user(): void
    {
        (new AuthorizationListener())->handle($this->context(new ProtectedFixturePayload()));

        $this->addToAssertionCount(1);
    }

    private function context(object $payload): RequestPipelineContext
    {
        $context = new RequestPipelineContext(
            requestDto: $payload,
            route: (new \ReflectionClass(DiscoveredRoute::class))->newInstanceWithoutConstructor(),
            request: new Request(method: 'GET', uri: '/secret', headers: [], query: [], post: [], server: [], cookies: []),
        );
        $context->authResult = AuthResult::successAsUser(new class implements AuthenticatableInterface {
            public function getId(): string { return 'user-1'; }
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return 'user-1'; }
        });

        return $context;
    }
}

#[AsProtectedPayload(path: '/fixture/permission-guarded', methods: ['GET'])]
#[RequiresPermission('admin.dangerous_action')]
final class PermissionGuardedFixturePayload
{
}

#[AsProtectedPayload(path: '/fixture/protected', methods: ['GET'])]
final class ProtectedFixturePayload
{
}

enum FixtureCapability: string implements CapabilityInterface
{
    case Dangerous = 'fixture.dangerous';
}

#[AsProtectedPayload(path: '/fixture/capability-guarded', methods: ['GET'])]
#[RequiresCapability(FixtureCapability::Dangerous)]
final class CapabilityGuardedFixturePayload
{
}

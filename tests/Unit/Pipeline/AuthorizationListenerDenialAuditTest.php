<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Pipeline;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Domain\Model\AccessDecision;
use Semitexa\Authorization\Domain\Enum\DenyReason;
use Semitexa\Authorization\Pipeline\AuthorizationListener;
use Semitexa\Core\Discovery\DiscoveredRoute;
use Semitexa\Core\Event\EventDispatcherInterface;
use Semitexa\Core\Pipeline\RequestPipelineContext;
use Semitexa\Core\Request;

/**
 * The denial-audit dispatch is defence-in-depth AND best-effort: a dead
 * audit sink must NEVER suppress or replace the access denial, but the
 * dispatch failure must not be silent either (an unlogged drop hides that
 * denials — including probing — are leaving no trail while the security log
 * looks clean). This pins the load-bearing half: a throwing audit dispatcher
 * cannot make emitDenied propagate — the deny path stays intact.
 */
final class AuthorizationListenerDenialAuditTest extends TestCase
{
    #[Test]
    public function a_throwing_audit_dispatch_never_escapes_the_denial_path(): void
    {
        $listener = new AuthorizationListener();

        $events = new class implements EventDispatcherInterface {
            public function create(string $eventClass, array $payload): object
            {
                throw new \RuntimeException('audit sink down');
            }

            public function dispatch(object $event): void
            {
                throw new \RuntimeException('audit sink down');
            }

            public function addPostDispatchHook(callable $hook): void
            {
            }
        };
        $slot = new \ReflectionProperty(AuthorizationListener::class, 'events');
        $slot->setValue($listener, $events);

        $context = new RequestPipelineContext(
            requestDto: new \stdClass(),
            route: (new \ReflectionClass(DiscoveredRoute::class))->newInstanceWithoutConstructor(),
            request: new Request(
                method: 'GET',
                uri: '/secret',
                headers: [],
                query: [],
                post: [],
                server: [],
                cookies: [],
            ),
        );

        $emitDenied = new \ReflectionMethod(AuthorizationListener::class, 'emitDenied');

        // The security invariant: the audit exception is swallowed (logged,
        // not silent) and never propagates out to suppress the denial.
        $emitDenied->invoke(
            $listener,
            AccessDecision::denyForbidden(DenyReason::PermissionRequired, 'nope'),
            $context,
            'user-1',
        );

        $this->addToAssertionCount(1); // reaching here == no exception escaped
    }
}

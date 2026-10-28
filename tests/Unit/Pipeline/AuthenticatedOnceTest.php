<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Pipeline;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Attribute\AsServicePayload;
use Semitexa\Authorization\Pipeline\GateAuthResult;
use Semitexa\Core\Attribute\AsPublicPayload;
use Semitexa\Authorization\Pipeline\AuthorizationListener;
use Semitexa\Authorization\Pipeline\PreHydrationAuthGate;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthenticatableInterface;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Auth\AuthResult;
use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Discovery\DiscoveredRoute;
use Semitexa\Core\Pipeline\RequestPipelineContext;
use Semitexa\Core\Request;
use Semitexa\Core\Support\CoroutineLocal;

/**
 * The pre-hydration gate and the authorization listener both ran the auth
 * handlers: two Argon2id checks for every machine request, and its use
 * recorded twice. The listener now takes what the gate found.
 */
final class AuthenticatedOnceTest extends TestCase
{
    /** @var array<string, mixed> what other tests left in the CLI store */
    private array $saved = [];

    /**
     * The gate writes CurrentRequestStore and its handoff into the CLI store:
     * kept from before the test and put back after it, so neither this class's
     * leftovers nor its clean start reach another test.
     */
    protected function setUp(): void
    {
        $this->saved = self::cliStore()->getValue();
        CoroutineLocal::resetCliStore();
    }

    protected function tearDown(): void
    {
        self::cliStore()->setValue(null, $this->saved);
    }

    private static function cliStore(): \ReflectionProperty
    {
        return new \ReflectionProperty(CoroutineLocal::class, 'cliStore');
    }

    #[Test]
    public function a_request_the_gate_authenticated_is_not_authenticated_again(): void
    {
        $auth = new CountingBootstrapper();
        $request = new Request('GET', '/svc', [], [], [], [], []);

        (new PreHydrationAuthGate())->gate(new OnceServicePayload(), $request, $auth);
        $context = new RequestPipelineContext(
            requestDto: new OnceServicePayload(),
            route: (new \ReflectionClass(DiscoveredRoute::class))->newInstanceWithoutConstructor(),
            request: $request,
            authBootstrapper: $auth,
        );
        (new AuthorizationListener())->handle($context);

        self::assertSame(1, $auth->calls);
        self::assertSame(
            [true, 'svc-1', AuthSubjectType::Service],
            [$context->authResult?->success, $context->authResult?->user?->getId(), $context->authResult?->subjectType],
            'the gate\'s principal, as a service',
        );
    }

    #[Test]
    public function another_request_does_not_inherit_what_the_gate_found(): void
    {
        $auth = new CountingBootstrapper();
        (new PreHydrationAuthGate())->gate(new OnceServicePayload(), new Request('GET', '/svc', [], [], [], [], []), $auth);

        $context = new RequestPipelineContext(
            requestDto: new OnceServicePayload(),
            route: (new \ReflectionClass(DiscoveredRoute::class))->newInstanceWithoutConstructor(),
            request: new Request('GET', '/svc', [], [], [], [], []),
            authBootstrapper: $auth,
        );
        (new AuthorizationListener())->handle($context);

        self::assertSame(2, $auth->calls);
    }

    #[Test]
    public function a_leftover_from_a_freed_request_reaches_no_later_one(): void
    {
        // The freed Request's object id goes to the next object made; the
        // handoff holds a weak reference, so it cannot match a stranger.
        $first = new Request('GET', '/svc', [], [], [], [], []);
        GateAuthResult::remember($first, (new CountingBootstrapper())->handle(new OnceServicePayload()));
        $firstId = spl_object_id($first);
        unset($first);
        $later = new Request('GET', '/svc', [], [], [], [], []);
        self::assertSame($firstId, spl_object_id($later), 'precondition: the id was reused');

        self::assertNull(GateAuthResult::takeFor($later));
    }

    #[Test]
    public function a_public_route_after_a_gated_one_does_not_inherit_its_identity(): void
    {
        $auth = new CountingBootstrapper();
        $request = new Request('GET', '/svc', [], [], [], [], []);
        (new PreHydrationAuthGate())->gate(new OnceServicePayload(), $request, $auth);

        // Same coroutine, same Request object, the next route is public: the gate clears what it held.
        (new PreHydrationAuthGate())->gate(new OncePublicPayload(), $request, $auth);

        self::assertNull(GateAuthResult::takeFor($request));
    }
}

#[AsServicePayload(path: '/svc', methods: ['GET'])]
final class OnceServicePayload
{
}

#[AsPublicPayload(path: '/open', methods: ['GET'])]
final class OncePublicPayload
{
}

final class CountingBootstrapper implements AuthBootstrapperInterface
{
    public int $calls = 0;

    public function isEnabled(): bool
    {
        return true;
    }

    public function handle(object $payload, AuthenticationMode $mode = AuthenticationMode::Mandatory): ?AuthResult
    {
        $this->calls++;

        return AuthResult::successAsService(new class implements AuthenticatableInterface {
            public function getId(): string { return 'svc-1'; }
            public function getAuthIdentifierName(): string { return 'id'; }
            public function getAuthIdentifier(): mixed { return 'svc-1'; }
        });
    }
}

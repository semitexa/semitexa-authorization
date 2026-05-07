<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Integration;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Auth\Context\AuthContextStore;
use Semitexa\Authorization\Domain\Model\CapabilityGrantSet;
use Semitexa\Authorization\Domain\Model\PermissionGrantSet;
use Semitexa\Authorization\Domain\Model\SubjectGrantSet;
use Semitexa\Core\Application;
use Semitexa\Core\Lifecycle\CurrentRequestStore;
use Semitexa\Core\Lifecycle\PerRequestStateRegistry;
use Semitexa\Core\Lifecycle\TestStateResetRegistry;
use Semitexa\Core\Request;
use Semitexa\Core\Support\CoroutineLocal;
use Semitexa\Core\Tenant\TenantContextStoreInterface;
use Semitexa\Locale\Context\LocaleContextStore;
use Semitexa\Modules\AuthDemo\Application\Service\AuthDemoStubAuthHandler;
use Semitexa\Modules\AuthDemo\Domain\Model\AuthDemoUser;
use Semitexa\Rbac\Application\Service\RbacDecisionCache;
use Semitexa\Tenancy\Context\TenantContext;
use Semitexa\Tenancy\Context\TenantContextStore;
use Semitexa\Webhooks\Auth\InMemoryWebhookReplayStore;
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use function Swoole\Coroutine\run;

/**
 * Concurrent-coroutine isolation under Swoole.
 *
 * Sequential lifecycle tests pin "between two requests, no leak". This file
 * pins the load-bearing Swoole assumption underneath all of them: when two
 * requests RUN AT THE SAME TIME on the same worker, one coroutine must
 * never observe the other's state — and cleanup in one coroutine must
 * never wipe the other's still-active state.
 *
 * Three scopes are exercised:
 *
 * 1. Primitive-level isolation — set state in coroutine A, set different
 *    state in coroutine B, prove each only sees its own. Pinned for every
 *    per-request store the framework owns: CurrentRequestStore,
 *    AuthContextStore, TenantContextStore, RbacDecisionCache, CoroutineLocal.
 *
 * 2. Cleanup-callback isolation — coroutine A sets state, coroutine B
 *    completes a full request lifecycle (which fires PerRequestStateRegistry
 *    and the CoroutineLocal end-of-request cleanup). Coroutine A's state
 *    must remain intact. Pinned with a Swoole channel barrier so the
 *    interleaving is deterministic, not timing-dependent.
 *
 * 3. End-to-end concurrent dispatch — production model: each coroutine
 *    creates its own `new Application()` and dispatches a real HTTP request.
 *    The same model SwooleBootstrap uses. No cross-coroutine bleed; each
 *    coroutine's request returns the right response.
 *
 * Webhook replay race: composing seen() + markSeen() as separate operations
 * is a check-then-act race — two concurrent coroutines can both pass the
 * seen() check before either calls markSeen(). The atomic markIfFirstSeen()
 * contract closes the window. The race shape and the atomic claim are
 * both pinned by tests below.
 */
#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class ConcurrentCoroutineIsolationTest extends TestCase
{
    /** @var list<class-string> */
    private const OPTIONAL_RUNTIME_CLASSES = [
        LocaleContextStore::class,
        AuthDemoStubAuthHandler::class,
        AuthDemoUser::class,
        RbacDecisionCache::class,
        TenantContext::class,
        TenantContextStore::class,
        InMemoryWebhookReplayStore::class,
    ];

    protected function setUp(): void
    {
        if (!class_exists(Coroutine::class, false)) {
            self::markTestSkipped('Swoole\\Coroutine not available — concurrent isolation cannot be verified');
        }
        foreach (self::OPTIONAL_RUNTIME_CLASSES as $class) {
            if (!class_exists($class)) {
                self::markTestSkipped(sprintf(
                    'Optional runtime dependency %s is unavailable in this package checkout',
                    $class,
                ));
            }
        }
        $this->wipeAll();
    }

    protected function tearDown(): void
    {
        $this->wipeAll();
    }

    private function wipeAll(): void
    {
        TestStateResetRegistry::resetAllForTesting();
        AuthContextStore::clear();
        AuthContextStore::clearFallback();
        TenantContextStore::shared()->clear();
        LocaleContextStore::clearFallback();
        CurrentRequestStore::clear();
        RbacDecisionCache::clear();
        CoroutineLocal::resetCliStore();
    }

    // ==================================================================
    //  Section A — primitive-level coroutine isolation
    // ==================================================================

    #[Test]
    public function current_request_store_is_coroutine_isolated(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            $reqA = $this->makeRequest('/a');
            $reqB = $this->makeRequest('/b');

            Coroutine::create(function () use (&$observed, $reqA): void {
                CurrentRequestStore::set($reqA);
                Coroutine::sleep(0.001); // yield so coroutine B can interleave
                $req = CurrentRequestStore::get();
                $observed['a'] = $req?->uri;
            });
            Coroutine::create(function () use (&$observed, $reqB): void {
                CurrentRequestStore::set($reqB);
                Coroutine::sleep(0.001);
                $req = CurrentRequestStore::get();
                $observed['b'] = $req?->uri;
            });
        });
        self::assertSame('/a', $observed['a']);
        self::assertSame('/b', $observed['b']);
    }

    #[Test]
    public function auth_context_store_is_coroutine_isolated(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            Coroutine::create(function () use (&$observed): void {
                AuthContextStore::setUser(new AuthDemoUser('user-a'));
                Coroutine::sleep(0.001);
                $observed['a'] = AuthContextStore::getUser()?->getAuthIdentifier();
            });
            Coroutine::create(function () use (&$observed): void {
                AuthContextStore::setUser(new AuthDemoUser('user-b'));
                Coroutine::sleep(0.001);
                $observed['b'] = AuthContextStore::getUser()?->getAuthIdentifier();
            });
        });
        self::assertSame('user-a', $observed['a']);
        self::assertSame('user-b', $observed['b']);
    }

    #[Test]
    public function tenant_context_store_is_coroutine_isolated(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            Coroutine::create(function () use (&$observed): void {
                TenantContextStore::shared()->set(TenantContext::fromResolution('tenant-a', 'host'));
                Coroutine::sleep(0.001);
                $observed['a'] = TenantContextStore::shared()->getOrFail()->getTenantId();
            });
            Coroutine::create(function () use (&$observed): void {
                TenantContextStore::shared()->set(TenantContext::fromResolution('tenant-b', 'host'));
                Coroutine::sleep(0.001);
                $observed['b'] = TenantContextStore::shared()->getOrFail()->getTenantId();
            });
        });
        self::assertSame('tenant-a', $observed['a']);
        self::assertSame('tenant-b', $observed['b']);
    }

    #[Test]
    public function rbac_decision_cache_is_coroutine_isolated(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            Coroutine::create(function () use (&$observed): void {
                RbacDecisionCache::set('shared-user-id', $this->grantsWithPermission('admin.tools'));
                Coroutine::sleep(0.001);
                $observed['a'] = $this->permissionList(RbacDecisionCache::get('shared-user-id'));
            });
            Coroutine::create(function () use (&$observed): void {
                RbacDecisionCache::set('shared-user-id', $this->grantsWithPermission('reports.view'));
                Coroutine::sleep(0.001);
                $observed['b'] = $this->permissionList(RbacDecisionCache::get('shared-user-id'));
            });
        });
        self::assertSame(['admin.tools'], $observed['a']);
        self::assertSame(['reports.view'], $observed['b']);
    }

    #[Test]
    public function coroutine_local_is_coroutine_isolated(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            Coroutine::create(function () use (&$observed): void {
                CoroutineLocal::set('concurrency-test.probe', 'a');
                Coroutine::sleep(0.001);
                $observed['a'] = CoroutineLocal::get('concurrency-test.probe');
            });
            Coroutine::create(function () use (&$observed): void {
                CoroutineLocal::set('concurrency-test.probe', 'b');
                Coroutine::sleep(0.001);
                $observed['b'] = CoroutineLocal::get('concurrency-test.probe');
            });
        });
        self::assertSame('a', $observed['a']);
        self::assertSame('b', $observed['b']);
    }

    // ==================================================================
    //  Section B — cleanup-callback isolation (channel-coordinated)
    // ==================================================================

    #[Test]
    public function per_request_registry_resetAll_in_coroutine_B_does_not_clear_coroutine_A(): void
    {
        $observed = ['a_user_after_b_reset' => null];
        run(function () use (&$observed): void {
            $cleanupDone = new Channel(1);
            $resumed = new Channel(1);

            Coroutine::create(function () use (&$observed, $cleanupDone, $resumed): void {
                AuthContextStore::setUser(new AuthDemoUser('coroutine-A-user'));
                $cleanupDone->pop(); // wait until B has done its full reset
                $observed['a_user_after_b_reset'] = AuthContextStore::getUser()?->getAuthIdentifier();
                $resumed->push(1);
            });
            Coroutine::create(function () use ($cleanupDone, $resumed): void {
                AuthContextStore::setUser(new AuthDemoUser('coroutine-B-user'));
                // B fires the same cleanup chain Application::handleRequest fires.
                PerRequestStateRegistry::resetAll();
                $cleanupDone->push(1);
                $resumed->pop();
            });
        });
        self::assertSame(
            'coroutine-A-user',
            $observed['a_user_after_b_reset'],
            'PerRequestStateRegistry::resetAll() in coroutine B wiped coroutine A state — cross-coroutine cleanup leak',
        );
    }

    #[Test]
    public function tenant_context_resetAll_in_coroutine_B_does_not_clear_coroutine_A(): void
    {
        $observed = ['a_after_b_reset' => null];
        run(function () use (&$observed): void {
            $cleanupDone = new Channel(1);
            $resumed = new Channel(1);

            Coroutine::create(function () use (&$observed, $cleanupDone, $resumed): void {
                TenantContextStore::shared()->set(TenantContext::fromResolution('tenant-A-active', 'host'));
                $cleanupDone->pop();
                $tenant = TenantContextStore::shared()->tryGet();
                $observed['a_after_b_reset'] = $tenant?->getTenantId();
                $resumed->push(1);
            });
            Coroutine::create(function () use ($cleanupDone, $resumed): void {
                TenantContextStore::shared()->set(TenantContext::fromResolution('tenant-B-active', 'host'));
                PerRequestStateRegistry::resetAll();
                $cleanupDone->push(1);
                $resumed->pop();
            });
        });
        self::assertSame(
            'tenant-A-active',
            $observed['a_after_b_reset'],
            'TenantContextStore reset in coroutine B wiped coroutine A',
        );
    }

    #[Test]
    public function coroutine_local_endRequest_in_coroutine_B_does_not_clear_coroutine_A(): void
    {
        $observed = ['a_after_b_end' => null];
        run(function () use (&$observed): void {
            $cleanupDone = new Channel(1);
            $resumed = new Channel(1);

            Coroutine::create(function () use (&$observed, $cleanupDone, $resumed): void {
                CoroutineLocal::set('concurrency-test.cleanup-probe', 'A');
                $cleanupDone->pop();
                $observed['a_after_b_end'] = CoroutineLocal::get('concurrency-test.cleanup-probe');
                $resumed->push(1);
            });
            Coroutine::create(function () use ($cleanupDone, $resumed): void {
                CoroutineLocal::set('concurrency-test.cleanup-probe', 'B');
                CoroutineLocal::endRequest(); // last step in Application::handleRequest finally
                $cleanupDone->push(1);
                $resumed->pop();
            });
        });
        self::assertSame(
            'A',
            $observed['a_after_b_end'],
            'CoroutineLocal::endRequest in coroutine B wiped coroutine A — cross-coroutine CLI-fallback wipe',
        );
    }

    // ==================================================================
    //  Section C — end-to-end concurrent dispatches (production model)
    // ==================================================================

    #[Test]
    public function two_concurrent_anonymous_dispatches_with_different_headers_do_not_leak(): void
    {
        $observed = ['a' => null, 'b' => null];
        run(function () use (&$observed): void {
            $barrier = new Channel(2);
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                $req = $this->makeRequest('/playground', ['X-Smoke-Probe' => 'a']);
                $resp = $app->handleRequest($req);
                $observed['a'] = $resp->getStatusCode();
                $barrier->push(1);
            });
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                $req = $this->makeRequest('/playground', ['X-Smoke-Probe' => 'b']);
                $resp = $app->handleRequest($req);
                $observed['b'] = $resp->getStatusCode();
                $barrier->push(1);
            });
            $barrier->pop();
            $barrier->pop();
        });
        self::assertNotNull($observed['a'], 'coroutine A did not complete');
        self::assertNotNull($observed['b'], 'coroutine B did not complete');
        self::assertLessThan(500, $observed['a']);
        self::assertLessThan(500, $observed['b']);
    }

    #[Test]
    public function concurrent_user_and_anonymous_dispatches_do_not_leak_user_identity(): void
    {
        $observed = ['user' => null, 'guest' => null];
        run(function () use (&$observed): void {
            $barrier = new Channel(2);
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                $req = $this->makeRequest(
                    '/auth-demo/runtime/protected',
                    [AuthDemoStubAuthHandler::HEADER => AuthDemoStubAuthHandler::USER_PREFIX . 'concurrent-user'],
                );
                $resp = $app->handleRequest($req);
                $observed['user'] = $resp->getStatusCode();
                $barrier->push(1);
            });
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                $req = $this->makeRequest('/auth-demo/runtime/protected'); // no auth
                $resp = $app->handleRequest($req);
                $observed['guest'] = $resp->getStatusCode();
                $barrier->push(1);
            });
            $barrier->pop();
            $barrier->pop();
        });
        self::assertSame(200, $observed['user'], 'authenticated user must succeed');
        self::assertSame(401, $observed['guest'], 'anonymous concurrent dispatch must be rejected as guest, not as the user');
    }

    #[Test]
    public function concurrent_user_and_service_dispatches_keep_subject_type_isolated(): void
    {
        $observed = ['user_status' => null, 'service_status' => null];
        run(function () use (&$observed): void {
            $barrier = new Channel(2);
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                $req = $this->makeRequest(
                    '/auth-demo/runtime/protected',
                    [AuthDemoStubAuthHandler::HEADER => AuthDemoStubAuthHandler::USER_PREFIX . 'overlap-user'],
                );
                $observed['user_status'] = $app->handleRequest($req)->getStatusCode();
                $barrier->push(1);
            });
            Coroutine::create(function () use (&$observed, $barrier): void {
                $app = new Application();
                // Service token on a USER-protected route → 401 because subject types must match.
                $req = $this->makeRequest(
                    '/auth-demo/runtime/protected',
                    [AuthDemoStubAuthHandler::HEADER => AuthDemoStubAuthHandler::SERVICE_PREFIX . 'overlap-service'],
                );
                $observed['service_status'] = $app->handleRequest($req)->getStatusCode();
                $barrier->push(1);
            });
            $barrier->pop();
            $barrier->pop();
        });
        self::assertSame(200, $observed['user_status'], 'user dispatch should succeed even with concurrent service request');
        self::assertSame(401, $observed['service_status'], 'service token on user-protected route must reject regardless of concurrent traffic');
    }

    #[Test]
    public function concurrent_dispatches_leave_zero_state_when_both_complete(): void
    {
        run(function (): void {
            $barrier = new Channel(2);
            Coroutine::create(function () use ($barrier): void {
                (new Application())->handleRequest($this->makeRequest('/playground'));
                $barrier->push(1);
            });
            Coroutine::create(function () use ($barrier): void {
                (new Application())->handleRequest($this->makeRequest('/__semitexa/error/404'));
                $barrier->push(1);
            });
            $barrier->pop();
            $barrier->pop();
        });
        // No coroutine state remains in CLI fallbacks/coroutine context after the
        // outer run() returns. Pin that by reading the static fallbacks.
        self::assertNull(AuthContextStore::getUser());
        self::assertNull(TenantContextStore::shared()->tryGet());
        self::assertNull(CurrentRequestStore::get());
    }

    #[Test]
    public function repeated_concurrent_bursts_remain_isolated(): void
    {
        // Sustained-load shape: 8 sequential bursts of 4 concurrent dispatches.
        // If state leakage existed between coroutines or between bursts, it would
        // surface as a non-200 in the user-token slot or a cross-burst id mix-up.
        $bursts = 8;
        $perBurst = 4;
        $observed = [];
        run(function () use ($bursts, $perBurst, &$observed): void {
            for ($burst = 0; $burst < $bursts; $burst++) {
                $barrier = new Channel($perBurst);
                for ($i = 0; $i < $perBurst; $i++) {
                    $tag = "b{$burst}-c{$i}";
                    Coroutine::create(function () use ($tag, $barrier, &$observed): void {
                        $app = new Application();
                        $req = $this->makeRequest(
                            '/auth-demo/runtime/protected',
                            [AuthDemoStubAuthHandler::HEADER => AuthDemoStubAuthHandler::USER_PREFIX . $tag],
                        );
                        $observed[$tag] = $app->handleRequest($req)->getStatusCode();
                        $barrier->push(1);
                    });
                }
                for ($i = 0; $i < $perBurst; $i++) {
                    $barrier->pop();
                }
            }
        });
        self::assertCount($bursts * $perBurst, $observed);
        foreach ($observed as $tag => $status) {
            self::assertSame(200, $status, "concurrent dispatch {$tag} returned {$status}");
        }
    }

    // ==================================================================
    //  Section D — webhook replay race + atomic-fix verification
    // ==================================================================

    #[Test]
    public function replay_store_atomic_markIfFirstSeen_lets_only_one_coroutine_in(): void
    {
        // Two coroutines both try to claim the same key. Exactly one must
        // win. This is the atomic claim contract.
        $store = new InMemoryWebhookReplayStore();
        $store->clear();

        $results = ['a' => null, 'b' => null];
        run(function () use ($store, &$results): void {
            $started = new Channel(2);
            $proceed = new Channel(2);

            Coroutine::create(function () use ($store, &$results, $started, $proceed): void {
                $started->push(1);
                $proceed->pop();
                $results['a'] = $store->markIfFirstSeen('concurrent-event-1');
            });
            Coroutine::create(function () use ($store, &$results, $started, $proceed): void {
                $started->push(1);
                $proceed->pop();
                $results['b'] = $store->markIfFirstSeen('concurrent-event-1');
            });

            $started->pop();
            $started->pop();
            $proceed->push(1);
            $proceed->push(1);
        });

        $wins = (int) $results['a'] + (int) $results['b'];
        self::assertSame(1, $wins, 'exactly one coroutine must win the atomic claim, got A=' . var_export($results['a'], true) . ' B=' . var_export($results['b'], true));
        self::assertTrue($store->seen('concurrent-event-1'), 'key must be seen after the winner marks it');
    }

    #[Test]
    public function replay_store_seen_then_markSeen_is_documented_unsafe_for_concurrent_use(): void
    {
        // The legacy two-call pattern (seen() then markSeen()) is a check-then-act
        // race. With a controlled barrier we can show both coroutines pass the
        // seen() check and both proceed to markSeen — i.e. both would have
        // executed the side effect in real handler code. The atomic
        // markIfFirstSeen() API exists precisely so handlers don't fall into
        // this trap. Pin the unsafety so anyone reintroducing the pattern
        // sees a regression.
        $store = new InMemoryWebhookReplayStore();
        $store->clear();

        $bothPassedSeenCheck = false;
        run(function () use ($store, &$bothPassedSeenCheck): void {
            $aPassedSeen = new Channel(1);
            $bPassedSeen = new Channel(1);

            Coroutine::create(function () use ($store, $aPassedSeen, $bPassedSeen, &$bothPassedSeenCheck): void {
                $alreadyKnown = $store->seen('legacy-race-key');
                $aPassedSeen->push(!$alreadyKnown);
                $bDecision = $bPassedSeen->pop();
                if ($bDecision && !$alreadyKnown) {
                    // both saw "not yet seen" — proves race
                    $bothPassedSeenCheck = true;
                }
                $store->markSeen('legacy-race-key'); // late mark — too late
            });
            Coroutine::create(function () use ($store, $aPassedSeen, $bPassedSeen): void {
                $alreadyKnown = $store->seen('legacy-race-key');
                $bPassedSeen->push(!$alreadyKnown);
                $aPassedSeen->pop();
                $store->markSeen('legacy-race-key');
            });
        });

        self::assertTrue(
            $bothPassedSeenCheck,
            'legacy seen()-then-markSeen() pattern is supposed to be unsafe — got safe somehow, did the contract change?',
        );
    }

    // ==================================================================
    //  Helpers
    // ==================================================================

    private function makeRequest(string $path, array $extraHeaders = []): Request
    {
        $headers = ['Accept' => 'application/json'] + $extraHeaders;
        return new Request(
            method: 'GET',
            uri: $path,
            headers: $headers,
            query: [],
            post: [],
            server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path],
            cookies: [],
            content: null,
        );
    }

    private function grantsWithPermission(string $perm): SubjectGrantSet
    {
        return new SubjectGrantSet(
            new CapabilityGrantSet([]),
            new PermissionGrantSet([$perm]),
        );
    }

    /** @return list<string> */
    private function permissionList(?SubjectGrantSet $grants): array
    {
        if ($grants === null) {
            return [];
        }
        return $grants->permissions->all();
    }
}

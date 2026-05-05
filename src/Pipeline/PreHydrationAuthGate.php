<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Application\Service\PayloadAccessPolicyResolver;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Auth\PayloadAccessType;
use Semitexa\Core\Attribute\ExecutionScoped;
use Semitexa\Core\Attribute\InjectAsMutable;
use Semitexa\Core\Pipeline\Exception\AuthenticationRequiredException;
use Semitexa\Core\Pipeline\PreHydrationAuthGateInterface;
use Semitexa\Core\Lifecycle\CurrentRequestStore;
use Semitexa\Core\Request;

/**
 * Runs auth before payload hydration so protected routes reject guests before
 * the framework parses or validates the request body.
 *
 * Closes the DoS window identified as finding S-3 in the audit: without this
 * gate, `RouteExecutor` hydrated and validated the payload before the
 * AuthorizationListener got a chance to enforce the policy, letting
 * unauthenticated clients force hydration work on every protected route.
 *
 * Public routes pass through untouched; the AuthorizationListener in the
 * AuthCheck pipeline phase still evaluates the full policy (permissions,
 * capabilities) after hydration.
 */
#[SatisfiesServiceContract(of: PreHydrationAuthGateInterface::class)]
#[ExecutionScoped]
final class PreHydrationAuthGate implements PreHydrationAuthGateInterface
{
    #[InjectAsMutable]
    protected AuthContextInterface $authContext;

    public function gate(object $barePayload, Request $request, ?AuthBootstrapperInterface $authBootstrapper): void
    {
        $resolver = new PayloadAccessPolicyResolver();

        // Validate metadata once per class (cached). Invalid attribute combos
        // (missing access type, multiple access types, public/service combined
        // with capability/permission grants) fail loudly here rather than
        // silently at the later listener.
        $resolver->assertValidMetadata($barePayload);

        $accessType = $resolver->accessType($barePayload);

        // Public payloads bypass the gate entirely.
        if ($accessType === PayloadAccessType::Public) {
            return;
        }

        // Make the HTTP request available to AuthHandlers BEFORE hydration so
        // header-based handlers (e.g. MachineAuthHandler reading
        // `Authorization: Bearer …`) can authenticate at the gate.
        //
        // Two delivery paths:
        //   - CurrentRequestStore: coroutine-local store every auth handler
        //     can read regardless of payload shape. This is the canonical
        //     mechanism — no payload boilerplate required.
        //   - Payload setHttpRequest: kept for backward compatibility with
        //     payloads that already implement the setHttpRequest convention.
        //     Idempotent with the post-hydration setHttpRequest call.
        CurrentRequestStore::set($request);
        if (method_exists($barePayload, 'setHttpRequest')) {
            $barePayload->setHttpRequest($request);
        }

        // No bootstrapper wired: fall through to the legacy post-hydration
        // listener. This preserves behaviour for early-stage apps that have
        // not yet enabled authentication; the AuthorizationListener will
        // reject the guest there with the same domain-specific message.
        if ($authBootstrapper === null || !$authBootstrapper->isEnabled()) {
            return;
        }

        $result = $authBootstrapper->handle($barePayload, AuthenticationMode::Mandatory);

        // Default-deny for unknown subject types. A handler that succeeds
        // without declaring a subjectType is treated as User domain — the
        // historical default for handlers that predate the subjectType
        // contract.
        if ($result?->success === true && $result->user !== null) {
            $subjectType = $result->subjectType ?? \Semitexa\Core\Auth\AuthSubjectType::User;

            if ($subjectType->satisfies($accessType)) {
                return;
            }

            // Successful auth, wrong domain. Do NOT silently let it through.
            // 401 with a domain-specific message so client tooling can correct
            // the credential. (Choosing 401 over 403 keeps the contract
            // "authentication is required AND must be of the right kind" —
            // 403 would be reserved for sufficient auth + insufficient grant.)
            throw new AuthenticationRequiredException(
                $accessType === PayloadAccessType::Service
                    ? 'Service authentication required'
                    : 'User authentication required',
            );
        }

        // Some apps push the principal through AuthContext via a
        // SessionPhase rather than per-request handlers. Honor that path —
        // but again only when the principal's domain matches the access type.
        if (isset($this->authContext) && !$this->authContext->isGuest()) {
            // AuthContext does not currently carry a subject type; in absence
            // of one, treat session-set users as User domain. Service
            // payloads still require a service-domain handler to succeed.
            if ($accessType === PayloadAccessType::Protected) {
                return;
            }
        }

        $message = $accessType === PayloadAccessType::Service
            ? 'Service authentication required'
            : 'Authentication required';

        throw new AuthenticationRequiredException($message);
    }
}

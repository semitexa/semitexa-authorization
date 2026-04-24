<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Policy\PayloadAccessPolicyResolver;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Attribute\ExecutionScoped;
use Semitexa\Core\Attribute\InjectAsMutable;
use Semitexa\Core\Pipeline\Exception\AuthenticationRequiredException;
use Semitexa\Core\Pipeline\PreHydrationAuthGateInterface;
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
        // fail loudly here rather than silently at the later listener.
        $resolver->assertValidMetadata($barePayload);

        if ($resolver->isPublic($barePayload)) {
            return;
        }

        // No bootstrapper wired: fall through to the legacy post-hydration gate.
        // This preserves behaviour for applications that have not yet enabled
        // authentication.
        if ($authBootstrapper === null || !$authBootstrapper->isEnabled()) {
            return;
        }

        $result = $authBootstrapper->handle($barePayload, AuthenticationMode::Mandatory);

        if ($result?->success === true && $result->user !== null) {
            return;
        }

        if (isset($this->authContext) && !$this->authContext->isGuest()) {
            return;
        }

        throw new AuthenticationRequiredException('Authentication required');
    }
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Domain\Contract\AuthorizerInterface;
use Semitexa\Authorization\Domain\Enum\DenyReason;
use Semitexa\Authorization\Domain\Event\AuthorizationDenied;
use Semitexa\Authorization\Application\Service\PayloadAccessPolicyResolver;
use Semitexa\Authorization\Domain\Model\AuthenticatedSubject;
use Semitexa\Authorization\Domain\Model\GuestSubject;
use Semitexa\Core\Attribute\AsPipelineListener;
use Semitexa\Core\Attribute\InjectAsMutable;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Auth\AuthBootstrapperInterface;
use Semitexa\Core\Auth\AuthContextInterface;
use Semitexa\Core\Auth\AuthenticationMode;
use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Auth\PayloadAccessType;
use Semitexa\Core\Event\EventDispatcherInterface;
use Semitexa\Core\Pipeline\AuthCheck;
use Semitexa\Core\Pipeline\Exception\AccessDeniedException;
use Semitexa\Core\Pipeline\Exception\AuthenticationRequiredException;
use Semitexa\Core\Pipeline\PipelineListenerInterface;
use Semitexa\Core\Pipeline\RequestPipelineContext;

/**
 * Single enforcement point for the authorization policy model.
 *
 * Responsibilities (orchestration only — no policy semantics inline):
 *   1. Resolve payload access policy.
 *   2. Validate policy metadata (boot-time invariant, fails loudly on bad combos).
 *   3. Invoke AuthBootstrapper in the appropriate mode (Mandatory or BestEffort).
 *   4. Evaluate the resolved subject against the access policy.
 *   5. Emit AuthorizationDenied event on denial (observational only).
 *   6. Map the decision to continuation, AuthenticationRequiredException, or AccessDeniedException.
 */
#[AsPipelineListener(phase: AuthCheck::class, priority: 0)]
final class AuthorizationListener implements PipelineListenerInterface
{
    #[InjectAsReadonly]
    protected AuthorizerInterface $authorizer;

    #[InjectAsReadonly]
    protected EventDispatcherInterface $events;

    #[InjectAsMutable]
    protected AuthContextInterface $authContext;

    public function handle(RequestPipelineContext $context): void
    {
        $resolver = new PayloadAccessPolicyResolver();

        // Validate metadata — fails loudly on contradictory attribute combinations.
        // This is a boot-time invariant enforced on the first request per payload class.
        $resolver->assertValidMetadata($context->requestDto);

        $policy = new \Semitexa\Authorization\Domain\Model\AccessPolicy(
            accessType: $resolver->accessType($context->requestDto),
            requiredCapabilities: $resolver->requiredCapabilities($context->requestDto),
            requiredPermissions: $resolver->requiredPermissions($context->requestDto),
        );

        $authBootstrapper = $context->authBootstrapper instanceof AuthBootstrapperInterface
            ? $context->authBootstrapper
            : null;

        if ($authBootstrapper !== null && $authBootstrapper->isEnabled()) {
            $mode = $policy->isPublic()
                ? AuthenticationMode::BestEffort
                : AuthenticationMode::Mandatory;

            $context->authResult = $authBootstrapper->handle($context->requestDto, $mode);
        }

        // Subject-domain enforcement: a successful auth from the wrong domain
        // (User token on a Service route, or Service token on a Protected route)
        // must NOT continue. The pre-hydration gate already rejects these in
        // most cases, but the listener is the second line of defense and the
        // only one that runs for routes without a registered gate.
        $authResult = $context->authResult;
        if (!$policy->isPublic()
            && $authResult?->success === true
            && $authResult->user !== null
        ) {
            $subjectType = $authResult->subjectType ?? AuthSubjectType::User;
            if (!$subjectType->satisfies($policy->accessType)) {
                throw new AuthenticationRequiredException(
                    $policy->accessType === PayloadAccessType::Service
                        ? 'Service authentication required'
                        : 'User authentication required',
                );
            }
        }

        $subject = $this->resolveSubject($context);

        if (!isset($this->authorizer)) {
            // No authorizer registered — fall back to simple public/protected check.
            if (!$policy->isPublic() && $subject->isGuest()) {
                throw new AuthenticationRequiredException('Authentication required');
            }
            return;
        }

        $decision = $this->authorizer->authorize($subject, $policy);

        if ($decision->allowed) {
            return;
        }

        $this->emitDenied($decision, $context, $subject->getIdentifier());

        if ($decision->denyReason === DenyReason::AuthenticationRequired) {
            throw new AuthenticationRequiredException($decision->message);
        }

        throw new AccessDeniedException($decision->message);
    }

    /**
     * Resolve the pipeline subject from the injected AuthContextInterface.
     * Falls back to a guest subject when no auth context is wired.
     *
     * Cycle-10: the AuthSubjectType from AuthResult is propagated onto the
     * AuthenticatedSubject so SubjectGrantResolver can route to the right
     * provider (User → CapabilityProviderInterface; Service →
     * ServiceCapabilityProviderInterface) and the RbacDecisionCache key
     * cannot collide between domains.
     */
    private function resolveSubject(RequestPipelineContext $context): AuthenticatedSubject|GuestSubject
    {
        $authResultSubjectType = $context->authResult?->subjectType;

        if (isset($this->authContext) && !$this->authContext->isGuest()) {
            return new AuthenticatedSubject(
                $this->authContext->getUser()?->getId() ?? '',
                $authResultSubjectType,
            );
        }

        $userId = $context->authResult?->success === true
            ? ($context->authResult->user?->getId() ?? '')
            : '';

        if ($userId === '') {
            return new GuestSubject();
        }

        return new AuthenticatedSubject($userId, $authResultSubjectType);
    }

    private function emitDenied(
        \Semitexa\Authorization\Domain\Model\AccessDecision $decision,
        RequestPipelineContext $context,
        ?string $userId,
    ): void {
        if (!isset($this->events)) {
            return;
        }

        try {
            $this->events->dispatch(new AuthorizationDenied(
                decision: $decision,
                payloadClass: $context->requestDto::class,
                routePath: $context->request->getUri(),
                userId: $userId,
                requestId: null,
            ));
        } catch (\Throwable) {
            // Audit failure must never suppress the denial response.
        }
    }
}

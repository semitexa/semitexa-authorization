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
            isPublic: $resolver->isPublic($context->requestDto),
            requiredCapabilities: $resolver->requiredCapabilities($context->requestDto),
            requiredPermissions: $resolver->requiredPermissions($context->requestDto),
        );

        $authBootstrapper = $context->authBootstrapper instanceof AuthBootstrapperInterface
            ? $context->authBootstrapper
            : null;

        if ($authBootstrapper !== null && $authBootstrapper->isEnabled()) {
            $mode = $policy->isPublic
                ? AuthenticationMode::BestEffort
                : AuthenticationMode::Mandatory;

            $context->authResult = $authBootstrapper->handle($context->requestDto, $mode);
        }

        $subject = $this->resolveSubject($context);

        if (!isset($this->authorizer)) {
            // No authorizer registered — fall back to simple public/protected check.
            if (!$policy->isPublic && $subject->isGuest()) {
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
     */
    private function resolveSubject(RequestPipelineContext $context): AuthenticatedSubject|GuestSubject
    {
        if (isset($this->authContext) && !$this->authContext->isGuest()) {
            return new AuthenticatedSubject($this->authContext->getUser()?->getId() ?? '');
        }

        $userId = $context->authResult?->success === true
            ? ($context->authResult->user?->getId() ?? '')
            : '';

        if ($userId === '') {
            return new GuestSubject();
        }

        return new AuthenticatedSubject($userId);
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

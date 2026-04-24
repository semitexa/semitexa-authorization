<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Authorizer;

use Semitexa\Authorization\Decision\AccessDecision;
use Semitexa\Authorization\Decision\DenyReason;
use Semitexa\Authorization\Policy\AccessPolicy;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Attribute\SatisfiesServiceContract;
use Semitexa\Core\Authorization\SubjectInterface;

#[SatisfiesServiceContract(of: AuthorizerInterface::class)]
final class Authorizer implements AuthorizerInterface
{
    #[InjectAsReadonly]
    protected SubjectGrantResolverInterface $grantResolver;

    public function authorize(SubjectInterface $subject, AccessPolicy $policy): AccessDecision
    {
        // Step 1: public endpoint — allow regardless of authentication state
        if ($policy->isPublic) {
            return AccessDecision::allow();
        }

        // Step 2: protected endpoint — authenticated subject required
        if ($subject->isGuest()) {
            return AccessDecision::denyAuthRequired();
        }

        // Steps 3 & 4: capability and permission checks only apply when required
        $needsGrants = $policy->requiredCapabilities !== [] || $policy->requiredPermissions !== [];

        if (!$needsGrants) {
            return AccessDecision::allow();
        }

        $grants = $this->grantResolver?->resolve($subject);

        // Step 3: capability checks (coarse-grained, fast)
        foreach ($policy->requiredCapabilities as $capability) {
            if ($grants === null || !$grants->capabilities->has($capability)) {
                return AccessDecision::denyForbidden(
                    DenyReason::CapabilityRequired,
                    'Missing required capability.',
                );
            }
        }

        // Step 4: slug-based permission checks (fine-grained)
        foreach ($policy->requiredPermissions as $permission) {
            if ($grants === null || !$grants->permissions->has($permission)) {
                return AccessDecision::denyForbidden(
                    DenyReason::PermissionRequired,
                    "Missing permission: {$permission}",
                );
            }
        }

        return AccessDecision::allow();
    }
}

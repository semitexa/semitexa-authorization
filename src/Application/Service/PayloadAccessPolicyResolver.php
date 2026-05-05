<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Application\Service;

use ReflectionClass;
use Semitexa\Authorization\Attribute\AsProtectedPayload;
use Semitexa\Authorization\Attribute\AsServicePayload;
use Semitexa\Authorization\Attribute\RequiresCapability;
use Semitexa\Authorization\Attribute\RequiresPermission;
use Semitexa\Authorization\Domain\Contract\CapabilityInterface;
use Semitexa\Authorization\Domain\Contract\PayloadAccessPolicyResolverInterface;
use Semitexa\Authorization\Domain\Model\AccessPolicy;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Attribute\AsPublicPayload;
use Semitexa\Core\Auth\PayloadAccessType;

final class PayloadAccessPolicyResolver implements PayloadAccessPolicyResolverInterface
{
    /** @var array<class-string, AccessPolicy> Worker-scoped cache — immutable after boot. */
    private static array $cache = [];

    public function isPublic(object $payload): bool
    {
        return $this->resolve($payload)->isPublic();
    }

    /** @return list<CapabilityInterface> */
    public function requiredCapabilities(object $payload): array
    {
        return $this->resolve($payload)->requiredCapabilities;
    }

    /** @return list<string> */
    public function requiredPermissions(object $payload): array
    {
        return $this->resolve($payload)->requiredPermissions;
    }

    public function accessType(object $payload): PayloadAccessType
    {
        return $this->resolve($payload)->accessType;
    }

    /**
     * Boot-time / per-route validation. Throws InvalidArgumentException with the
     * offending payload FQCN when the access metadata is incoherent.
     *
     * Enforced rules:
     *   1. Exactly one #[AsPublicPayload]/#[AsProtectedPayload]/#[AsServicePayload]
     *      attribute is required (the same instance / one of those subclasses,
     *      counted across the class hierarchy).
     *   2. Multiple access attributes on the same payload are rejected.
     *   3. #[AsPublicPayload] cannot be combined with #[RequiresCapability]
     *      or #[RequiresPermission] (public means anonymous — there is no
     *      principal to evaluate the grant against).
     *   4. #[AsServicePayload] CAN be combined with #[RequiresCapability]
     *      (capabilities are resolved through ServiceCapabilityProviderInterface
     *      for service principals; same enum cases work across both providers —
     *      isolation is at the provider/grant layer, not the requirement layer).
     *   5. #[AsServicePayload] cannot be combined with #[RequiresPermission]
     *      (permissions remain user-domain only; service authorization is
     *      capability-based).
     *   6. #[AsProtectedPayload] may freely be combined with both attributes.
     */
    public function assertValidMetadata(object $payload): void
    {
        // Force a fresh classification so this method is callable independently
        // of cached resolve() output (the resolve path already throws on
        // missing/multiple access attrs; assertValidMetadata adds the
        // domain-specific combination guards).
        $policy = $this->resolve($payload);

        if ($policy->isPublic()) {
            $this->rejectAllAuthRequirementsOnPublic($payload, $policy);
        }

        if ($policy->isService()) {
            $this->rejectPermissionsOnService($payload, $policy);
        }
    }

    /**
     * Public payloads must not declare any auth requirement — neither
     * capability nor permission. There is no authenticated principal to
     * evaluate against, so the requirement would be unsatisfiable.
     */
    private function rejectAllAuthRequirementsOnPublic(object $payload, AccessPolicy $policy): void
    {
        if ($policy->requiredCapabilities !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares #[AsPublicPayload] together with #[RequiresCapability], which is invalid. '
                . 'Public endpoints have no authenticated principal; declare #[AsProtectedPayload] (user) '
                . 'or #[AsServicePayload] (service) if a capability is required.',
                $payload::class,
            ));
        }

        if ($policy->requiredPermissions !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares #[AsPublicPayload] together with #[RequiresPermission], which is invalid. '
                . 'Public endpoints have no authenticated principal; declare #[AsProtectedPayload] '
                . 'if a permission is required.',
                $payload::class,
            ));
        }
    }

    /**
     * Service payloads can carry #[RequiresCapability] — resolved through
     * ServiceCapabilityProviderInterface — but #[RequiresPermission] is
     * user-domain only. A service route that needs fine-grained
     * authorization should use a Service capability.
     */
    private function rejectPermissionsOnService(object $payload, AccessPolicy $policy): void
    {
        if ($policy->requiredPermissions !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares #[AsServicePayload] together with #[RequiresPermission], which is invalid. '
                . '#[RequiresPermission] is user-domain only; service routes use #[RequiresCapability] '
                . 'with a ServiceCapabilityProviderInterface implementation.',
                $payload::class,
            ));
        }
    }

    private function rejectAuthRequirementsOn(object $payload, AccessPolicy $policy, string $attributeShortName): void
    {
        // Retained for backwards compatibility with any external caller; new
        // call sites use the more specific helpers above.
        if ($policy->requiredCapabilities !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares #[%s] together with #[RequiresCapability], which is invalid. '
                . '#[RequiresCapability] only applies to #[AsProtectedPayload]; '
                . 'declare exactly one of #[AsPublicPayload], #[AsProtectedPayload], or #[AsServicePayload].',
                $payload::class,
                $attributeShortName,
            ));
        }

        if ($policy->requiredPermissions !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares #[%s] together with #[RequiresPermission], which is invalid. '
                . '#[RequiresPermission] only applies to #[AsProtectedPayload]; '
                . 'declare exactly one of #[AsPublicPayload], #[AsProtectedPayload], or #[AsServicePayload].',
                $payload::class,
                $attributeShortName,
            ));
        }
    }

    private function resolve(object $payload): AccessPolicy
    {
        $class = $payload::class;

        if (isset(self::$cache[$class])) {
            return self::$cache[$class];
        }

        $accessAttributes = [];
        $capabilities = [];
        $permissions = [];

        $ref = new ReflectionClass($payload);
        $current = $ref;
        while ($current !== false) {
            // Access attributes: gather from the class hierarchy. Multiple
            // declarations across the chain still count as multiple — there is
            // no inheritance override; the contract is "exactly one".
            $found = $current->getAttributes(AbstractPayloadRoute::class, \ReflectionAttribute::IS_INSTANCEOF);
            foreach ($found as $attr) {
                $accessAttributes[] = [
                    'name' => $attr->getName(),
                    'instance' => $attr->newInstance(),
                ];
            }

            foreach ($current->getAttributes(RequiresCapability::class) as $attr) {
                $capabilities[] = $attr->newInstance()->capability;
            }

            foreach ($current->getAttributes(RequiresPermission::class) as $attr) {
                $permissions[] = $attr->newInstance()->permission;
            }

            $current = $current->getParentClass();
        }

        if ($accessAttributes === []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s has no payload-access attribute. '
                . 'Declare exactly one of #[%s], #[%s], or #[%s].',
                $class,
                AsPublicPayload::class,
                AsProtectedPayload::class,
                AsServicePayload::class,
            ));
        }

        if (count($accessAttributes) > 1) {
            $declared = implode(', ', array_map(
                static fn (array $a): string => '#[' . $a['name'] . ']',
                $accessAttributes,
            ));
            throw new \InvalidArgumentException(sprintf(
                'Payload %s declares multiple payload-access attributes: %s. '
                . 'Declare exactly one of #[%s], #[%s], or #[%s].',
                $class,
                $declared,
                AsPublicPayload::class,
                AsProtectedPayload::class,
                AsServicePayload::class,
            ));
        }

        /** @var AbstractPayloadRoute $accessAttr */
        $accessAttr = $accessAttributes[0]['instance'];

        $policy = new AccessPolicy(
            accessType: $accessAttr->getAccessType(),
            requiredCapabilities: $capabilities,
            requiredPermissions: $permissions,
        );

        self::$cache[$class] = $policy;
        return $policy;
    }

    public static function clearCache(): void
    {
        self::$cache = [];
    }
}

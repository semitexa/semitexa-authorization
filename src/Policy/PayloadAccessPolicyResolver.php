<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Policy;

use Semitexa\Authorization\Attributes\PublicEndpoint;
use Semitexa\Authorization\Attributes\RequiresCapability;
use Semitexa\Authorization\Attributes\RequiresPermission;
use Semitexa\Authorization\Capability\Capability;

final class PayloadAccessPolicyResolver implements PayloadAccessPolicyResolverInterface
{
    /** @var array<class-string, AccessPolicy> Worker-scoped cache — immutable after boot. */
    private static array $cache = [];

    public function isPublic(object $payload): bool
    {
        return $this->resolve($payload)->isPublic;
    }

    /** @return list<Capability> */
    public function requiredCapabilities(object $payload): array
    {
        return $this->resolve($payload)->requiredCapabilities;
    }

    /** @return list<string> */
    public function requiredPermissions(object $payload): array
    {
        return $this->resolve($payload)->requiredPermissions;
    }

    public function assertValidMetadata(object $payload): void
    {
        $policy = $this->resolve($payload);

        if (!$policy->isPublic) {
            return;
        }

        if ($policy->requiredCapabilities !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s has both #[PublicEndpoint] and #[RequiresCapability], which is invalid. '
                . 'A public endpoint cannot also require a capability.',
                $payload::class,
            ));
        }

        if ($policy->requiredPermissions !== []) {
            throw new \InvalidArgumentException(sprintf(
                'Payload %s has both #[PublicEndpoint] and #[RequiresPermission], which is invalid. '
                . 'A public endpoint cannot also require a permission.',
                $payload::class,
            ));
        }
    }

    private function resolve(object $payload): AccessPolicy
    {
        $class = $payload::class;

        if (isset(self::$cache[$class])) {
            return self::$cache[$class];
        }

        $isPublic = false;
        $capabilities = [];
        $permissions = [];

        $ref = new \ReflectionClass($payload);
        while ($ref !== false) {
            if (!$isPublic && $ref->getAttributes(PublicEndpoint::class) !== []) {
                $isPublic = true;
            }

            foreach ($ref->getAttributes(RequiresCapability::class) as $attr) {
                $capabilities[] = $attr->newInstance()->capability;
            }

            foreach ($ref->getAttributes(RequiresPermission::class) as $attr) {
                $permissions[] = $attr->newInstance()->permission;
            }

            $ref = $ref->getParentClass();
        }

        $policy = new AccessPolicy(
            isPublic: $isPublic,
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

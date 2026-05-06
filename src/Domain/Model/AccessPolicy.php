<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;
use Semitexa\Core\Auth\PayloadAccessType;

/**
 * Resolved access policy for a specific payload.
 *
 * `accessType` is the single source of truth — set by exactly one of
 * #[AsPublicPayload], #[AsProtectedPayload], #[AsServicePayload]. Capability
 * and permission grants apply only to Protected payloads; combining them with
 * Public or Service is rejected by PayloadAccessPolicyResolver::assertValidMetadata.
 */
final readonly class AccessPolicy
{
    /**
     * @param list<CapabilityInterface> $requiredCapabilities
     * @param list<string>              $requiredPermissions
     */
    public function __construct(
        public PayloadAccessType $accessType,
        public array $requiredCapabilities,
        public array $requiredPermissions,
    ) {}

    public function isPublic(): bool
    {
        return $this->accessType === PayloadAccessType::Public;
    }

    public function isProtected(): bool
    {
        return $this->accessType === PayloadAccessType::Protected;
    }

    public function isService(): bool
    {
        return $this->accessType === PayloadAccessType::Service;
    }
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Authorization\Domain\Contract\SubjectGrantResolverInterface;

/**
 * Holds both capability and permission grants for a subject.
 *
 * Returned by SubjectGrantResolverInterface and used by Authorizer
 * to evaluate capability and permission requirements.
 */
final readonly class SubjectGrantSet
{
    public function __construct(
        public CapabilityGrantSet $capabilities,
        public PermissionGrantSet $permissions,
    ) {}
}

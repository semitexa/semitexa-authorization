<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Authorizer;

use Semitexa\Authorization\Grant\SubjectGrantSet;
use Semitexa\Core\Authorization\SubjectInterface;

/**
 * Resolves the capability and permission grants for a given subject.
 *
 * The interface lives in semitexa-authorization so the Authorizer can depend
 * on it without creating a circular package dependency. The implementation
 * lives in semitexa-rbac.
 */
interface SubjectGrantResolverInterface
{
    public function resolve(SubjectInterface $subject): SubjectGrantSet;
}

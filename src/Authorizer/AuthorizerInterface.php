<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Authorizer;

use Semitexa\Authorization\Decision\AccessDecision;
use Semitexa\Authorization\Policy\AccessPolicy;
use Semitexa\Core\Authorization\SubjectInterface;

interface AuthorizerInterface
{
    public function authorize(SubjectInterface $subject, AccessPolicy $policy): AccessDecision;
}

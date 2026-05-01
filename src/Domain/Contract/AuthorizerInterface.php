<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Contract;

use Semitexa\Authorization\Domain\Model\AccessDecision;
use Semitexa\Authorization\Domain\Model\AccessPolicy;
use Semitexa\Core\Authorization\SubjectInterface;

interface AuthorizerInterface
{
    public function authorize(SubjectInterface $subject, AccessPolicy $policy): AccessDecision;
}

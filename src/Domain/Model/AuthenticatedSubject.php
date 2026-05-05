<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Authorization\SubjectInterface;

final readonly class AuthenticatedSubject implements SubjectInterface
{
    public function __construct(
        private string $identifier,
        private ?AuthSubjectType $subjectType = null,
    ) {}

    public function isGuest(): bool
    {
        return false;
    }

    public function getIdentifier(): ?string
    {
        return $this->identifier;
    }

    public function getSubjectType(): ?AuthSubjectType
    {
        return $this->subjectType;
    }
}

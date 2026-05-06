<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Core\Auth\AuthSubjectType;
use Semitexa\Core\Authorization\SubjectInterface;

final class GuestSubject implements SubjectInterface
{
    public function isGuest(): bool
    {
        return true;
    }

    public function getIdentifier(): ?string
    {
        return null;
    }

    public function getSubjectType(): ?AuthSubjectType
    {
        return null;
    }
}

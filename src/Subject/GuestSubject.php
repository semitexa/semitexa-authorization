<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Subject;

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
}

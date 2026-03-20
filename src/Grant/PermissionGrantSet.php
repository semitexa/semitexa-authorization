<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Grant;

/**
 * Holds the set of slug-based permissions granted to a subject.
 *
 * Permission slugs are strings like 'users.manage' or 'settings.smtp.update'.
 * The database-backed implementation lives in semitexa-rbac.
 */
final readonly class PermissionGrantSet
{
    /** @param list<string> $permissions */
    public function __construct(private array $permissions) {}

    public function has(string $permission): bool
    {
        return in_array($permission, $this->permissions, true);
    }

    /** @return list<string> */
    public function all(): array
    {
        return $this->permissions;
    }
}

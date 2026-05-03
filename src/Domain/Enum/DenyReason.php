<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Enum;

enum DenyReason: string
{
    /**
     * The endpoint requires authentication but the subject is a guest.
     * Maps to HTTP 401.
     */
    case AuthenticationRequired = 'auth_required';

    /**
     * The authenticated subject lacks a required capability.
     * Maps to HTTP 403.
     */
    case CapabilityRequired = 'capability_required';

    /**
     * The authenticated subject lacks a required slug-based permission.
     * Maps to HTTP 403.
     */
    case PermissionRequired = 'missing_permission';

    /**
     * The payload has invalid or contradictory authorization metadata.
     * This is a developer error — fails at boot-time.
     * Maps to HTTP 500 / boot failure.
     */
    case InvalidPolicyMetadata = 'invalid_policy_metadata';
}

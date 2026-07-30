<?php

declare(strict_types=1);

namespace Semitexa\Authorization;

use Semitexa\Core\Attribute\Capability;

/**
 * What this package offers, for the capability catalog.
 *
 * Without this the package is invisible to anyone whose project has not
 * installed it - which is precisely the audience worth telling, since they are
 * the ones about to build it by hand. The convention is one `Capabilities` class
 * per package: a definite place to look, and a definite place for a guard to
 * check.
 *
 * Nothing reads this at runtime.
 */
#[Capability(
    id: 'authorization.access',
    summary: 'Declarative access decisions: #[RequiresPermission] and #[RequiresCapability] on payloads, gated before hydration.',
    useWhen: 'Whether an action is allowed depends on the subject, and the answer must not be re-derived per handler.',
    avoidWhen: 'Everyone authenticated may do everything - a route-level auth level is enough.',
    replaces: [
        'an if on the user role at the top of every handler',
        'an access check that runs after the payload is hydrated, too late to be a gate',
    ],
    seeAlso: 'semitexa/rbac',
)]
final class Capabilities
{
}

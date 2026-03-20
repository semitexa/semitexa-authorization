<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Decision\DenyReason;
use Semitexa\Authorization\Event\AuthorizationDenied;
use Semitexa\Core\Attributes\AsEventListener;

/**
 * Observational listener for denied authorization attempts.
 *
 * Responsibilities:
 *   - Record structured security telemetry for denied requests.
 *   - Increment counters, emit logs, dispatch alerts.
 *   - Never alter the access decision — strictly read-only.
 *
 * This listener runs after AuthorizationListener emits AuthorizationDenied.
 * The denial has already been decided; this listener only observes.
 */
#[AsEventListener(event: AuthorizationDenied::class)]
final class AuthorizationAuditListener
{
    public function handle(AuthorizationDenied $event): void
    {
        $denialType = $event->decision->denyReason?->value ?? 'unknown';

        error_log(sprintf(
            '[authorization] denied payload=%s path=%s reason=%s user=%s',
            $event->payloadClass,
            $event->routePath,
            $denialType,
            $event->userId ?? 'guest',
        ));
    }
}

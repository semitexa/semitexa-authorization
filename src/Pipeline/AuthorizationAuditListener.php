<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Event\AuthorizationDenied;
use Semitexa\Core\Attribute\AsEventListener;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Log\LoggerInterface;

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
    #[InjectAsReadonly]
    protected LoggerInterface $logger;

    public function handle(AuthorizationDenied $event): void
    {
        $this->logger->notice('Authorization denied', [
            'payload' => $event->payloadClass,
            'path' => $event->routePath,
            'reason' => $event->decision->denyReason?->value ?? 'unknown',
            'user' => $event->userId ?? 'guest',
        ]);
    }
}

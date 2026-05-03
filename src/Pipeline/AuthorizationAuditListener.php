<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Pipeline;

use Semitexa\Authorization\Domain\Event\AuthorizationDenied;
use Semitexa\Core\Attribute\AsEventListener;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Log\FallbackErrorLogger;
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
        $context = [
            'payload' => $event->payloadClass,
            'path' => $this->sanitizeRoutePath($event->routePath),
            'reason' => $event->decision->denyReason?->value ?? 'unknown',
            'user' => $event->userId ?? 'guest',
            'request_id' => $event->requestId ?? 'n/a',
        ];

        if (isset($this->logger)) {
            $this->logger->notice('Authorization denied', $context);
            return;
        }

        FallbackErrorLogger::log('Authorization denied', $context);
    }

    private function sanitizeRoutePath(string $routePath): string
    {
        $path = parse_url($routePath, PHP_URL_PATH);

        return is_string($path) && $path !== '' ? $path : $routePath;
    }
}

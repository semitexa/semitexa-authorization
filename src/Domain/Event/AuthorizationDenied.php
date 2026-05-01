<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Event;

use Semitexa\Authorization\Domain\Model\AccessDecision;

/**
 * Emitted when an authorization decision denies a request.
 *
 * This event is strictly observational — it does not alter the denial.
 * AuthorizationAuditListener receives this event and records structured
 * security telemetry without affecting the pipeline outcome.
 */
final class AuthorizationDenied
{
    public function __construct(
        public readonly AccessDecision $decision,
        public readonly string $payloadClass,
        public readonly string $routePath,
        public readonly ?string $userId,
        public readonly ?string $requestId,
    ) {}
}

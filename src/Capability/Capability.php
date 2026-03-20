<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Capability;

/**
 * Marker interface for capability enums.
 *
 * Capabilities are coarse-grained, code-level grants that determine whether
 * a subject may access a broad class of endpoint behavior. They are declared
 * as PHP backed enums implementing this interface.
 *
 * Example:
 *
 *   enum AdminCapability: string implements Capability {
 *       case Access = 'admin.access';
 *       case Settings = 'admin.settings';
 *   }
 *
 * The bitmask storage model is internal to semitexa-rbac.
 * The public boundary remains Capability enum values.
 */
interface Capability
{
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Grant;

use Semitexa\Authorization\Capability\Capability;

/**
 * Holds the set of capabilities granted to a subject.
 *
 * The bitmask implementation detail is internal to semitexa-rbac.
 * This type carries the evaluated result: which Capability values
 * the current subject holds.
 */
final readonly class CapabilityGrantSet
{
    /** @param list<Capability> $capabilities */
    public function __construct(private array $capabilities) {}

    public function has(Capability $capability): bool
    {
        foreach ($this->capabilities as $granted) {
            if ($granted === $capability) {
                return true;
            }
        }
        return false;
    }

    /** @return list<Capability> */
    public function all(): array
    {
        return $this->capabilities;
    }
}

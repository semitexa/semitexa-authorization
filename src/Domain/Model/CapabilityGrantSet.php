<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Domain\Model;

use Semitexa\Authorization\Domain\Contract\CapabilityInterface;

/**
 * Holds the set of capabilities granted to a subject.
 *
 * The bitmask implementation detail is internal to semitexa-rbac.
 * This type carries the evaluated result: which CapabilityInterface values
 * the current subject holds.
 */
final readonly class CapabilityGrantSet
{
    /** @param list<CapabilityInterface> $capabilities */
    public function __construct(private array $capabilities) {}

    public function has(CapabilityInterface $capability): bool
    {
        foreach ($this->capabilities as $granted) {
            if ($granted === $capability) {
                return true;
            }
        }
        return false;
    }

    /** @return list<CapabilityInterface> */
    public function all(): array
    {
        return $this->capabilities;
    }
}

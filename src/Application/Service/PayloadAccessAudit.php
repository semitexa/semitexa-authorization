<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Application\Service;

/**
 * Applies {@see PayloadAccessPolicyResolver::assertValidMetadata()} to every
 * route payload at once.
 *
 * At runtime the same rules run on a route's first request (the gate and the
 * listener both call them), which is the only moment a never-requested route
 * gets checked. This audit is that check for the whole route table, with no
 * request: lint:access runs it, and so does ai:verify.
 *
 * The payload is built without its constructor — the resolver reads class
 * attributes only, and a payload's constructor may want request state.
 */
final class PayloadAccessAudit
{
    /**
     * @param iterable<array<string, mixed>> $routes route rows as the discovery returns them
     * @return array{checked: int, violations: list<array{path: string, class: string, reason: string}>}
     */
    public function audit(iterable $routes): array
    {
        $paths = [];
        foreach ($routes as $route) {
            $class = (string) ($route['class'] ?? '');
            if ($class === '') {
                continue;
            }
            $paths[$class] ??= (string) ($route['path'] ?? '');
        }
        ksort($paths);

        $resolver = new PayloadAccessPolicyResolver();
        $violations = [];
        foreach ($paths as $class => $path) {
            $reason = $this->refusal($resolver, $class);
            if ($reason !== null) {
                $violations[] = ['path' => $path, 'class' => $class, 'reason' => $reason];
            }
        }

        return ['checked' => count($paths), 'violations' => $violations];
    }

    private function refusal(PayloadAccessPolicyResolver $resolver, string $class): ?string
    {
        if (!class_exists($class)) {
            return "payload class {$class} does not exist";
        }
        try {
            $payload = (new \ReflectionClass($class))->newInstanceWithoutConstructor();
            $resolver->assertValidMetadata($payload);
        } catch (\Throwable $e) {
            return $e->getMessage();
        }

        return null;
    }
}

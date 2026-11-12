<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service\Fixture;

use Attribute;
use Semitexa\Core\Attribute\AbstractPayloadRoute;
use Semitexa\Core\Auth\PayloadAccessType;
use Semitexa\Core\Contract\DeclaresRequiredPermissionsInterface;

/** A route attribute that states its own permission, the way #[AsCrud(permission: 'users')] does. */
#[Attribute(Attribute::TARGET_CLASS)]
final class PermissionRouteFixture extends AbstractPayloadRoute implements DeclaresRequiredPermissionsInterface
{
    public function __construct(public readonly string $permission)
    {
        parent::__construct(path: '/fixture/screen', methods: ['GET']);
    }

    public function getAccessType(): PayloadAccessType
    {
        return PayloadAccessType::Protected;
    }

    public function requiredPermissions(string $payloadClass): array
    {
        return [$this->permission . '.read'];
    }
}

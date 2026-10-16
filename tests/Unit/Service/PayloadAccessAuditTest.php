<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Tests\Unit\Service;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Semitexa\Authorization\Application\Service\PayloadAccessAudit;
use Semitexa\Authorization\Application\Service\PayloadAccessPolicyResolver;
use Semitexa\Authorization\Attribute\AsProtectedPayload;
use Semitexa\Authorization\Attribute\AsServicePayload;
use Semitexa\Authorization\Attribute\RequiresCapability;
use Semitexa\Authorization\Attribute\RequiresPermission;
use Semitexa\Authorization\Tests\Unit\Pipeline\FixtureCapability;
use Semitexa\Core\Attribute\AsPublicPayload;

/**
 * lint:access refuses, for the whole route table and without a request, the
 * payloads the runtime would refuse on their first request.
 */
final class PayloadAccessAuditTest extends TestCase
{
    protected function tearDown(): void
    {
        PayloadAccessPolicyResolver::clearCache();
    }

    #[Test]
    public function valid_payloads_pass_and_each_class_is_checked_once(): void
    {
        $report = (new PayloadAccessAudit())->audit([
            ['path' => '/audit/public', 'class' => AuditPublicFixture::class],
            ['path' => '/audit/public', 'class' => AuditPublicFixture::class],
            ['path' => '/audit/protected', 'class' => AuditProtectedWithGrantsFixture::class],
            ['path' => '/audit/service', 'class' => AuditServiceWithCapabilityFixture::class],
        ]);

        self::assertSame(3, $report['checked']);
        self::assertSame([], $report['violations']);
    }

    #[Test]
    public function each_invalid_combination_is_reported_with_its_route(): void
    {
        $report = (new PayloadAccessAudit())->audit([
            ['path' => '/audit/public-capability', 'class' => AuditPublicWithCapabilityFixture::class],
            ['path' => '/audit/service-permission', 'class' => AuditServiceWithPermissionFixture::class],
            ['path' => '/audit/two-access', 'class' => AuditTwoAccessAttributesFixture::class],
            ['path' => '/audit/gone', 'class' => 'Semitexa\\Authorization\\Tests\\Unit\\Service\\NoSuchAuditPayload'],
        ]);

        self::assertSame(4, $report['checked']);
        $byPath = array_column($report['violations'], 'reason', 'path');
        self::assertCount(4, $byPath);
        self::assertStringContainsString('#[AsPublicPayload] together with #[RequiresCapability]', $byPath['/audit/public-capability']);
        self::assertStringContainsString('#[AsServicePayload] together with #[RequiresPermission]', $byPath['/audit/service-permission']);
        self::assertStringContainsString('multiple payload-access attributes', $byPath['/audit/two-access']);
        self::assertStringContainsString('does not exist', $byPath['/audit/gone']);
    }

    #[Test]
    public function a_payload_is_checked_without_running_its_constructor(): void
    {
        $report = (new PayloadAccessAudit())->audit([
            ['path' => '/audit/ctor', 'class' => AuditConstructorNeedsRequestFixture::class],
        ]);

        self::assertSame(1, $report['checked']);
        self::assertCount(1, $report['violations']);
        self::assertStringContainsString('#[RequiresPermission]', $report['violations'][0]['reason']);
    }
}

#[AsPublicPayload(path: '/audit/public')]
final class AuditPublicFixture
{
}

#[AsProtectedPayload(path: '/audit/protected')]
#[RequiresCapability(FixtureCapability::Dangerous)]
#[RequiresPermission('audit.view')]
final class AuditProtectedWithGrantsFixture
{
}

#[AsServicePayload(path: '/audit/service')]
#[RequiresCapability(FixtureCapability::Dangerous)]
final class AuditServiceWithCapabilityFixture
{
}

#[AsPublicPayload(path: '/audit/public-capability')]
#[RequiresCapability(FixtureCapability::Dangerous)]
final class AuditPublicWithCapabilityFixture
{
}

#[AsServicePayload(path: '/audit/service-permission')]
#[RequiresPermission('audit.view')]
final class AuditServiceWithPermissionFixture
{
}

#[AsPublicPayload(path: '/audit/two-access')]
#[AsProtectedPayload(path: '/audit/two-access')]
final class AuditTwoAccessAttributesFixture
{
}

#[AsPublicPayload(path: '/audit/ctor')]
#[RequiresPermission('audit.view')]
final class AuditConstructorNeedsRequestFixture
{
    public function __construct()
    {
        throw new \LogicException('built from a request only');
    }
}

<?php

declare(strict_types=1);

namespace Semitexa\Authorization\Application\Console\Command;

use Semitexa\Authorization\Application\Service\PayloadAccessAudit;
use Semitexa\Core\Attribute\AsCommand;
use Semitexa\Core\Attribute\InjectAsReadonly;
use Semitexa\Core\Console\BaseCommand;
use Semitexa\Core\Discovery\AttributeDiscovery;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Runs the access-metadata rules over the payload of every discovered route,
 * so an invalid combination is found before anyone requests the route.
 * See {@see PayloadAccessAudit}.
 */
#[AsCommand(
    name: 'lint:access',
    description: 'Check the access attributes of every route payload before the route is first requested.',
)]
final class LintAccessCommand extends BaseCommand
{
    /** Why this check exists, and what taught us; ai:verify prints it when the lint fails. */
    public const RATIONALE = 'Why: the access rules (exactly one of #[AsPublicPayload]/#[AsProtectedPayload]/#[AsServicePayload]; no grant on a public payload; no permission on a service payload) run on a route\'s FIRST REQUEST, so a broken route ships green and answers 500 to its first caller in production. Learned 2026-10-16 in the authorization#28 review: the docs said "at boot", the code said "per request".';

    #[InjectAsReadonly]
    protected AttributeDiscovery $attributeDiscovery;

    public function __construct()
    {
        parent::__construct('lint:access');
    }

    protected function configure(): void
    {
        $this->addOption('json', null, InputOption::VALUE_NONE, 'Emit JSON envelope');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $report = (new PayloadAccessAudit())->audit($this->attributeDiscovery->getRoutes());
        $violations = $report['violations'];

        if ((bool) $input->getOption('json')) {
            $output->writeln(json_encode([
                'artifact' => 'semitexa-authorization.lint-access/v1',
                'ok' => $violations === [],
                'checked' => $report['checked'],
                'violations' => $violations,
            ], JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), OutputInterface::OUTPUT_RAW);
            return $violations === [] ? Command::SUCCESS : Command::FAILURE;
        }

        foreach ($violations as $v) {
            $output->writeln(sprintf('<error>%s</error> %s', $v['path'], $v['class']));
            $output->writeln('  ' . $v['reason']);
        }
        if ($violations === []) {
            $output->writeln(sprintf('lint:access → %d route payload(s), every one declares valid access metadata.', $report['checked']));
            return Command::SUCCESS;
        }
        $output->writeln(sprintf('lint:access → %d of %d route payload(s) would be refused on their first request.', count($violations), $report['checked']));
        return Command::FAILURE;
    }
}

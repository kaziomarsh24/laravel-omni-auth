<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Console;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'omni:install {--force : Overwrite existing configuration and migration files}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and initialize Laravel OmniAuth with configuration and migrations';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('Initializing Laravel OmniAuth installation...');

        // 1. Publish configuration file
        $this->comment('Publishing configuration...');
        $configParams = ['--tag' => 'omni-auth-config'];
        if ($this->option('force')) {
            $configParams['--force'] = true;
        }
        $this->call('vendor:publish', $configParams);

        // 2. Publish database migrations
        $this->comment('Publishing database migrations...');
        $migrationParams = ['--tag' => 'omni-auth-migrations'];
        if ($this->option('force')) {
            $migrationParams['--force'] = true;
        }
        $this->call('vendor:publish', $migrationParams);

        // 3. Ensure Sanctum migrations are published for personal_access_tokens
        $sanctumParams = [
            '--provider' => 'Laravel\Sanctum\SanctumServiceProvider',
            '--tag' => 'sanctum-migrations',
        ];
        if ($this->option('force')) {
            $sanctumParams['--force'] = true;
        }
        $this->callSilent('vendor:publish', $sanctumParams);

        $this->info('OmniAuth configuration and migrations have been published successfully.');
        $this->line('');
        $this->line('Next steps:');
        $this->line('1. Ensure your User model uses the KaziOmar\OmniAuth\Traits\HasOmniAuth trait.');
        $this->line('2. Run database migrations: php artisan migrate');
        $this->line('3. Configure providers and options in config/omni-auth.php');

        return Command::SUCCESS;
    }
}

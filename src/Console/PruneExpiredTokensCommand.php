<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Console;

use Illuminate\Console\Command;
use KaziOmar\OmniAuth\Models\AuthDevice;
use Laravel\Sanctum\PersonalAccessToken;

class PruneExpiredTokensCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'omni:prune-tokens {--hours=24 : Number of hours beyond expiration to purge}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune expired Sanctum tokens and stale device sessions';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $hours = (int) $this->option('hours');
        $threshold = now()->subHours($hours);

        // 1. Prune expired PersonalAccessTokens
        $tokensDeleted = PersonalAccessToken::where('expires_at', '<', $threshold)->delete();

        // 2. Prune inactive device records older than 90 days with no active or existing tokens
        $staleDevicesThreshold = now()->subDays(90);
        $activeTokenIds = PersonalAccessToken::pluck('id')->all();

        $devicesDeleted = AuthDevice::where('last_active_at', '<', $staleDevicesThreshold)
            ->where(function ($query) use ($activeTokenIds) {
                $query->whereNull('token_id')
                    ->orWhereNotIn('token_id', $activeTokenIds);
            })
            ->delete();

        $this->info("Pruning completed: {$tokensDeleted} expired tokens and {$devicesDeleted} stale device records purged.");

        return Command::SUCCESS;
    }
}

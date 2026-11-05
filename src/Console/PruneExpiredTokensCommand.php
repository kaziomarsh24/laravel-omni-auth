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
    protected $signature = 'omni:prune-tokens {--hours= : Number of hours beyond expiration to purge} {--days= : Number of days beyond expiration to purge}';

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
        $daysOption = $this->option('days');
        $hoursOption = $this->option('hours');

        if ($daysOption !== null) {
            $days = (int) $daysOption;
            $threshold = now()->subDays($days);
            $staleDevicesThreshold = now()->subDays(max($days, 30));
        } elseif ($hoursOption !== null) {
            $hours = (int) $hoursOption;
            $threshold = now()->subHours($hours);
            $staleDevicesThreshold = now()->subDays(90);
        } else {
            $threshold = now()->subHours(24);
            $staleDevicesThreshold = now()->subDays(90);
        }

        // 1. Prune expired PersonalAccessTokens
        $tokensDeleted = PersonalAccessToken::where('expires_at', '<', $threshold)->delete();

        // 2. Prune inactive device records older than threshold with no active or existing tokens
        $devicesDeleted = AuthDevice::where('last_active_at', '<', $staleDevicesThreshold)
            ->where(function ($query) {
                $query->whereNull('token_id')
                    ->orWhereNotExists(function ($subQuery) {
                        $subQuery->selectRaw(1)
                            ->from('personal_access_tokens')
                            ->whereColumn('personal_access_tokens.id', 'auth_devices.token_id');
                    });
            })
            ->where(function ($query) {
                $query->whereNull('refresh_token_id')
                    ->orWhereNotExists(function ($subQuery) {
                        $subQuery->selectRaw(1)
                            ->from('personal_access_tokens')
                            ->whereColumn('personal_access_tokens.id', 'auth_devices.refresh_token_id');
                    });
            })
            ->delete();

        $this->info("Pruning completed: {$tokensDeleted} expired tokens and {$devicesDeleted} stale device records purged.");

        return Command::SUCCESS;
    }
}

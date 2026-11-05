<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $userModel = config('omni-auth.user_model', 'App\\Models\\User');
        $table = class_exists($userModel) ? (new $userModel())->getTable() : 'users';

        if (Schema::hasTable($table) && !Schema::hasColumn($table, 'password_set_at')) {
            Schema::table($table, function (Blueprint $table) {
                $table->timestamp('password_set_at')->nullable()->after('password');
            });

            // Backfill legacy users with an active password (excluding pure social-only signups)
            $socialOnlyUserIds = [];
            if (Schema::hasTable('auth_social_accounts')) {
                $socialOnlyUserIds = \Illuminate\Support\Facades\DB::table('auth_social_accounts')
                    ->where('data', 'like', '%"is_social_only":true%')
                    ->pluck('user_id')
                    ->all();
            }

            $query = \Illuminate\Support\Facades\DB::table($table)
                ->whereNotNull('password')
                ->where('password', '!=', '');

            if (!empty($socialOnlyUserIds)) {
                $query->whereNotIn('id', $socialOnlyUserIds);
            }

            $query->update(['password_set_at' => now()]);
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $userModel = config('omni-auth.user_model', 'App\\Models\\User');
        $table = class_exists($userModel) ? (new $userModel())->getTable() : 'users';

        if (Schema::hasTable($table) && Schema::hasColumn($table, 'password_set_at')) {
            Schema::table($table, function (Blueprint $table) {
                $table->dropColumn('password_set_at');
            });
        }
    }
};

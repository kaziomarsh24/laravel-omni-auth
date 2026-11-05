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
        if (Schema::hasTable('auth_devices') && !Schema::hasColumn('auth_devices', 'refresh_token_id')) {
            Schema::table('auth_devices', function (Blueprint $table) {
                $table->unsignedBigInteger('refresh_token_id')->nullable()->after('token_id')->index();
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasTable('auth_devices') && Schema::hasColumn('auth_devices', 'refresh_token_id')) {
            Schema::table('auth_devices', function (Blueprint $table) {
                $table->dropColumn('refresh_token_id');
            });
        }
    }
};

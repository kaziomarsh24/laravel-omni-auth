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

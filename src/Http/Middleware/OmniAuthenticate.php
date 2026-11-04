<?php

namespace KaziOmar\OmniAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class OmniAuthenticate
{
    /**
     * Handle an incoming request.
     *
     * Authenticates the request via configured guard (default: sanctum),
     * which transparently resolves tokens from Authorization Bearer headers
     * or HttpOnly cookies.
     */
    public function handle(Request $request, Closure $next, ...$guards): Response
    {
        $guard = empty($guards) ? config('omni-auth.guard', 'sanctum') : $guards[0];

        if (!auth($guard)->check()) {
            return response()->json([
                'ok' => false,
                'message' => 'Unauthenticated.',
            ], 401);
        }

        return $next($request);
    }
}

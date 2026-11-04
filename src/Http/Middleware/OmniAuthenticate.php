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

        // CSRF Guard for Cookie-Authenticated Web Requests:
        // When using HttpOnly cookies (no Bearer header) on state-changing operations (POST, PUT, PATCH, DELETE),
        // enforce presence of a custom anti-CSRF header (X-Requested-With, X-CSRF-TOKEN, X-Client-Type, or Origin match)
        // to prevent cross-site request forgery even when SameSite=None is configured.
        if (config('omni-auth.cookie.csrf_protection', true)) {
            $isBearer = (bool) $request->bearerToken();
            $cookieName = config('omni-auth.cookie.name', 'omni_access_token');
            $hasAuthCookie = (bool) $request->cookie($cookieName);

            if ($hasAuthCookie && !$isBearer && in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                $hasCustomHeader = $request->hasHeader('X-Requested-With')
                    || $request->hasHeader('X-CSRF-TOKEN')
                    || $request->hasHeader('X-XSRF-TOKEN')
                    || $request->hasHeader('X-Client-Type');

                $origin = $request->headers->get('Origin');
                $host = $request->getSchemeAndHttpHost();
                $originMatches = $origin && str_starts_with($origin, $host);

                if (!$hasCustomHeader && !$originMatches) {
                    return response()->json([
                        'ok' => false,
                        'message' => 'CSRF verification failed: Missing custom request header (X-Requested-With or X-Client-Type).',
                    ], 403);
                }
            }
        }

        return $next($request);
    }
}

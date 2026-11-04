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

        // C7: Set default guard and ensure $request->user() returns the authenticated user on stock Laravel
        auth()->shouldUse($guard);
        $user = auth($guard)->user();
        $request->setUserResolver(fn() => $user);

        // H1: Prevent Refresh Tokens from being used as Access Tokens
        if ($user && method_exists($user, 'currentAccessToken')) {
            $token = $user->currentAccessToken();
            if ($token instanceof \Laravel\Sanctum\PersonalAccessToken) {
                if ($token->name === 'refresh_token' || !$token->can('access-api')) {
                    return response()->json([
                        'ok' => false,
                        'message' => 'Invalid token capability. Refresh tokens cannot access protected API endpoints.',
                    ], 403);
                }
            }
        }

        // CSRF Guard for Cookie-Authenticated Web Requests:
        // When using HttpOnly cookies (no Bearer header) on state-changing operations (POST, PUT, PATCH, DELETE),
        // enforce presence of a custom anti-CSRF header or strict origin match
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
                $originMatches = false;

                // H5: Strict Origin comparison to avoid subdomain/prefix spoofing (e.g. localhost.evil.com)
                if ($origin) {
                    $originParts = parse_url($origin);
                    $hostParts = parse_url($request->getSchemeAndHttpHost());

                    $originMatches = ($originParts['scheme'] ?? '') === ($hostParts['scheme'] ?? '')
                        && ($originParts['host'] ?? '') === ($hostParts['host'] ?? '')
                        && ($originParts['port'] ?? null) === ($hostParts['port'] ?? null);
                }

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

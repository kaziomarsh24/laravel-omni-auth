<?php

namespace KaziOmar\OmniAuth\Services;

use Illuminate\Http\Request;

class ClientDetector
{
    /**
     * Determine whether the incoming request originates from a mobile application.
     */
    public function isMobile(Request $request): bool
    {
        $headerName = config('omni-auth.client_detection.header_name', 'X-Client-Type');
        $mobileValue = config('omni-auth.client_detection.mobile_value', 'mobile');

        // 1. Explicit Header Check (highest priority)
        if ($request->hasHeader($headerName)) {
            return strtolower((string) $request->header($headerName)) === strtolower($mobileValue);
        }

        // 2. If client explicitly requests Bearer JSON and does not accept cookies
        if ($request->hasHeader('Authorization') && str_starts_with((string) $request->header('Authorization'), 'Bearer ')) {
            return true;
        }

        // 3. User-Agent Heuristic (optional fallback)
        if (config('omni-auth.client_detection.inspect_user_agent', true)) {
            $userAgent = strtolower((string) $request->userAgent());

            // Check for native mobile client runtimes (Flutter, Dart, React Native, OkHttp, Dalvik, iOS CFNetwork)
            $nativeRuntimes = [
                'dart',
                'flutter',
                'okhttp',
                'dalvik',
                'cfnetwork',
                'alamofire',
                'postman', // Helpful in API testing tools
            ];

            foreach ($nativeRuntimes as $runtime) {
                if (str_contains($userAgent, $runtime)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Determine whether the incoming request originates from a web browser / SPA.
     */
    public function isWeb(Request $request): bool
    {
        return !$this->isMobile($request);
    }
}

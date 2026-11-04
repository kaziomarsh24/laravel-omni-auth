<?php

namespace KaziOmar\OmniAuth\Services;

use Illuminate\Http\Request;

class ClientDetector
{
    /**
     * Determine whether the incoming request originates from a mobile application or API client.
     */
    public function isMobile(Request $request): bool
    {
        $headerName = config('omni-auth.client_detection.header_name', 'X-Client-Type');
        $mobileValue = config('omni-auth.client_detection.mobile_value', 'mobile');

        // 1. Explicit Header Check (highest priority)
        if ($request->hasHeader($headerName)) {
            return strtolower((string) $request->header($headerName)) === strtolower($mobileValue);
        }

        // 2. If client explicitly requests Bearer JSON
        if ($request->hasHeader('Authorization') && str_starts_with((string) $request->header('Authorization'), 'Bearer ')) {
            return true;
        }

        // 3. User-Agent Heuristic for Native Mobile & API Testing Tools
        $userAgent = strtolower((string) $request->userAgent());

        $apiClients = [
            'dart',
            'flutter',
            'okhttp',
            'dalvik',
            'cfnetwork',
            'alamofire',
            'postman',
            'insomnia',
            'curl',
            'httpie',
        ];

        foreach ($apiClients as $client) {
            if (str_contains($userAgent, $client)) {
                return true;
            }
        }

        // 4. If request is pure API (expects JSON) and lacks common browser signatures
        if ($request->expectsJson() && !empty($userAgent)) {
            $isBrowser = str_contains($userAgent, 'mozilla') ||
                         str_contains($userAgent, 'chrome') ||
                         str_contains($userAgent, 'safari') ||
                         str_contains($userAgent, 'firefox') ||
                         str_contains($userAgent, 'edge');

            if (!$isBrowser) {
                return true;
            }
        }

        // 5. Configurable default fallback
        $defaultClient = config('omni-auth.client_detection.default_client', 'web');

        return strtolower($defaultClient) === 'mobile';
    }

    /**
     * Determine whether the incoming request originates from a web browser / SPA.
     */
    public function isWeb(Request $request): bool
    {
        return !$this->isMobile($request);
    }
}

<?php

declare(strict_types=1);

namespace KaziOmar\OmniAuth\Services;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

class CookieManager
{
    /**
     * Create an HttpOnly, Secure cookie for access tokens.
     */
    public function makeAccessTokenCookie(string $token, ?int $minutes = null, ?Request $request = null): Cookie
    {
        $name = config('omni-auth.cookie.name', 'omni_access_token');
        $minutes = $minutes ?? (int) config('omni-auth.tokens.access_token_ttl', 15);

        return $this->createCookie($name, $token, $minutes, $request);
    }

    /**
     * Create an HttpOnly, Secure cookie for refresh tokens.
     */
    public function makeRefreshTokenCookie(string $token, ?int $minutes = null, ?Request $request = null): Cookie
    {
        $name = config('omni-auth.cookie.refresh_name', 'omni_refresh_token');
        $minutes = $minutes ?? (int) config('omni-auth.tokens.refresh_token_ttl', 43200);

        return $this->createCookie($name, $token, $minutes, $request);
    }

    /**
     * Create an expired cookie to clear the access token.
     */
    public function makeForgetAccessTokenCookie(): Cookie
    {
        $name = config('omni-auth.cookie.name', 'omni_access_token');

        return $this->createCookie($name, '', -2628000);
    }

    /**
     * Create an expired cookie to clear the refresh token.
     */
    public function makeForgetRefreshTokenCookie(): Cookie
    {
        $name = config('omni-auth.cookie.refresh_name', 'omni_refresh_token');

        return $this->createCookie($name, '', -2628000);
    }

    /**
     * Attach access and optional refresh cookies to an HTTP response.
     */
    public function attachTokens(Response $response, string $accessToken, ?string $refreshToken = null, ?Request $request = null): Response
    {
        $response->headers->setCookie($this->makeAccessTokenCookie($accessToken, null, $request));

        if ($refreshToken !== null) {
            $response->headers->setCookie($this->makeRefreshTokenCookie($refreshToken, null, $request));
        }

        return $response;
    }

    /**
     * Attach expired cookies to an HTTP response to sign out the web client.
     */
    public function forgetTokens(Response $response): Response
    {
        $response->headers->setCookie($this->makeForgetAccessTokenCookie());
        $response->headers->setCookie($this->makeForgetRefreshTokenCookie());

        return $response;
    }

    /**
     * Retrieve the access token from the request cookie if present.
     */
    public function getAccessTokenFromCookie(Request $request): ?string
    {
        $name = config('omni-auth.cookie.name', 'omni_access_token');

        return $request->cookie($name);
    }

    /**
     * Retrieve the refresh token from the request cookie if present.
     */
    public function getRefreshTokenFromCookie(Request $request): ?string
    {
        $name = config('omni-auth.cookie.refresh_name', 'omni_refresh_token');

        return $request->cookie($name);
    }

    /**
     * Get the configured cookie names (useful for Laravel EncryptCookies $except array).
     */
    public function cookieNames(): array
    {
        return [
            config('omni-auth.cookie.name', 'omni_access_token'),
            config('omni-auth.cookie.refresh_name', 'omni_refresh_token'),
        ];
    }

    /**
     * Low-level helper to instantiate a Symfony Cookie with configured defaults.
     * Uses $request->isSecure() to reliably support AWS ALB, Cloudflare, Nginx, and Docker reverse proxies.
     */
    protected function createCookie(string $name, string $value, int $minutes, ?Request $request = null): Cookie
    {
        $expire = $minutes > 0 ? time() + ($minutes * 60) : time() - 3600;
        $path = config('omni-auth.cookie.path', '/');
        $domain = config('omni-auth.cookie.domain', null);
        
        $secureConfig = config('omni-auth.cookie.secure', null);
        
        // Fix 1: Reliably check HTTPS via request()->isSecure() which respects TrustProxies & X-Forwarded-Proto
        if ($secureConfig !== null) {
            $secure = (bool) $secureConfig;
        } else {
            $req = $request ?? (function_exists('request') ? request() : null);
            $secure = $req ? $req->isSecure() : false;
        }
        
        $httpOnly = (bool) config('omni-auth.cookie.http_only', true);
        $sameSite = config('omni-auth.cookie.same_site', 'lax');

        return new Cookie(
            name: $name,
            value: $value,
            expire: $expire,
            path: $path,
            domain: $domain,
            secure: $secure,
            httpOnly: $httpOnly,
            raw: false,
            sameSite: $sameSite
        );
    }
}

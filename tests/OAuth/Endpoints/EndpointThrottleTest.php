<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Endpoints\TokenEndpoint;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;
use VoltCMS\UserAccess\LoginThrottle;

/**
 * The lockout PLAN.md §5 asks for, on the endpoint where guessing actually pays: a client secret,
 * an authorization code or a code verifier can all be brute-forced at the token endpoint, and
 * nothing else in the package rate-limits them.
 *
 * `LoginThrottle` is voltcms/useraccess's, not a second implementation — but the key is built here
 * rather than through its `key()` helper, which reads `$_SERVER['REMOTE_ADDR']` directly. The peer
 * address arrives on the Request instead, so a test can vary it and an application behind a proxy
 * can decide for itself what it trusts.
 */
final class EndpointThrottleTest extends EndpointTestCase
{
    private const MAX_ATTEMPTS = 3;

    public function testAFailedExchangeIsAllowedUpToTheLimit(): void
    {
        $endpoint = $this->throttledTokenEndpoint();

        for ($attempt = 0; $attempt < self::MAX_ATTEMPTS; $attempt++) {
            $response = $endpoint->handle($this->badExchange());
        }

        $this->assertSame('invalid_grant', $response->decodedBody()['error'] ?? null);
    }

    public function testTheAttemptAfterTheLimitIsLockedOut(): void
    {
        $endpoint = $this->throttledTokenEndpoint();

        for ($attempt = 0; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $response = $endpoint->handle($this->badExchange());
        }

        $this->assertSame(Response::STATUS_TOO_MANY_REQUESTS, $response->status);
    }

    public function testALockoutIsKeyedToThePeerAddress(): void
    {
        $endpoint = $this->throttledTokenEndpoint();

        for ($attempt = 0; $attempt <= self::MAX_ATTEMPTS; $attempt++) {
            $endpoint->handle($this->badExchange());
        }

        $response = $endpoint->handle($this->badExchange(clientIp: '198.51.100.9'));

        $this->assertSame('invalid_grant', $response->decodedBody()['error'] ?? null);
    }

    public function testASuccessfulExchangeClearsTheCount(): void
    {
        $endpoint = $this->throttledTokenEndpoint();
        $code     = $this->approvedCode();

        $endpoint->handle($this->badExchange());
        $endpoint->handle($this->badExchange());

        $issued = $endpoint->handle(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $code,
            'code_verifier' => $this->codeVerifier,
        ], [], '203.0.113.4'));

        $this->assertSame('Bearer', $issued->decodedBody()['token_type'] ?? null);

        for ($attempt = 0; $attempt < self::MAX_ATTEMPTS; $attempt++) {
            $response = $endpoint->handle($this->badExchange());
        }

        $this->assertSame('invalid_grant', $response->decodedBody()['error'] ?? null);
    }

    // --- Helpers ---

    private function throttledTokenEndpoint(): TokenEndpoint
    {
        return new TokenEndpoint(
            $this->server,
            $this->configuration,
            new PsrAdapter(),
            null,
            new LoginThrottle($this->storageDirectory . '/throttle', self::MAX_ATTEMPTS, 900),
        );
    }

    private function badExchange(string $clientIp = '203.0.113.4'): Request
    {
        return new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => 'not-a-code',
            'code_verifier' => $this->codeVerifier,
        ], [], $clientIp);
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests;

use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuthServer;
use VoltCMS\MCP\Tests\Support\RecordingConsentView;
use VoltCMS\MCP\Tests\Support\RecordingLoginRedirector;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\MutableScopePolicy;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;

/**
 * SECURITY.md: *a token can never carry a scope its granting user's roles do not support*, and *a
 * deactivated account or a removed role invalidates a live token now, not at expiry.*
 *
 * The authorize endpoint keeps both for the authorization-code flow, because it narrows the request
 * before anyone consents. It cannot keep either for the REFRESH flow — a refresh happens with no
 * browser and no consent screen — so `ScopeRepository::finalizeScopes()` re-checks there, and these
 * are the tests that say so. Without them a user demoted after consenting would keep being handed
 * their old scopes for as long as they kept refreshing.
 */
final class OAuthServerScopeNarrowingTest extends RepositoryTestCase
{
    private const CLIENT_ID    = 'claude-desktop';
    private const REDIRECT_URI = 'https://claude.ai/callback';

    private RecordingConsentView $consentView;
    private string $codeVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->consentView  = new RecordingConsentView();
        $this->codeVerifier = bin2hex(random_bytes(32));
    }

    public function testARefreshAfterADemotionCarriesOnlyTheScopesTheAccountStillGrants(): void
    {
        $policy = new MutableScopePolicy(['mcp:read', 'mcp:write']);
        $oauth  = $this->oauth(scopePolicy: $policy);
        $issued = $this->issue($oauth);

        $policy->scopes = ['mcp:read'];

        $refreshed = $this->refresh($oauth, (string) $issued['refresh_token']);

        $this->assertSame(['mcp:read'], $oauth->accessTokenVerifier()->verify((string) $refreshed['access_token'])?->scopes);
    }

    public function testARefreshByAnAccountThatGrantsNothingIsRefused(): void
    {
        $policy = new MutableScopePolicy(['mcp:read', 'mcp:write']);
        $oauth  = $this->oauth(scopePolicy: $policy);
        $issued = $this->issue($oauth);

        $policy->scopes = [];

        $this->assertSame('invalid_grant', $this->refresh($oauth, (string) $issued['refresh_token'])['error'] ?? null);
    }

    public function testARefreshByADeactivatedAccountIsRefused(): void
    {
        $identities = new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor']));
        $oauth      = $this->oauth(identities: $identities);
        $issued     = $this->issue($oauth);

        $identities->forget('jannis');

        $this->assertSame('invalid_grant', $this->refresh($oauth, (string) $issued['refresh_token'])['error'] ?? null);
    }

    public function testARefreshByAnAccountThatIsStillIntactSucceeds(): void
    {
        $oauth  = $this->oauth();
        $issued = $this->issue($oauth);

        $this->assertSame('Bearer', $this->refresh($oauth, (string) $issued['refresh_token'])['token_type'] ?? null);
    }

    // --- Helpers ---

    private function oauth(?IdentityProviderInterface $identities = null, ?ScopePolicyInterface $scopePolicy = null): OAuthServer
    {
        $oauth = new OAuthServer(
            $this->configuration,
            $identities ?? new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            $scopePolicy ?? new StubScopePolicy(['mcp:read', 'mcp:write']),
            $this->consentView,
            new RecordingLoginRedirector(),
        );

        $oauth->clients()->save(new Client(self::CLIENT_ID, 'Claude Desktop', [self::REDIRECT_URI]));

        return $oauth;
    }

    /**
     * @return array<string, mixed>
     */
    private function issue(OAuthServer $oauth): array
    {
        $query = [
            'response_type'         => 'code',
            'client_id'             => self::CLIENT_ID,
            'redirect_uri'          => self::REDIRECT_URI,
            'scope'                 => 'mcp:read mcp:write',
            'state'                 => 'xyz',
            'code_challenge'        => rtrim(strtr(base64_encode(hash('sha256', $this->codeVerifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];

        $uri = '/oauth/authorize?' . http_build_query($query);

        $oauth->authorize(new Request('GET', $uri, $query));

        $redirect = $oauth->authorize(new Request('POST', $uri, $query, [
            ConsentRequest::FIELD_TICKET   => $this->consentView->ticket(),
            ConsentRequest::FIELD_DECISION => ConsentRequest::DECISION_APPROVE,
        ]));

        parse_str((string) parse_url((string) $redirect->header('Location'), PHP_URL_QUERY), $parameters);

        $this->assertIsString($parameters['code'] ?? null, 'The redirect carried no authorization code.');

        return $oauth->token(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $parameters['code'],
            'code_verifier' => $this->codeVerifier,
        ]))->decodedBody();
    }

    /**
     * @return array<string, mixed>
     */
    private function refresh(OAuthServer $oauth, string $refreshToken): array
    {
        return $oauth->token(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'refresh_token',
            'client_id'     => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
        ]))->decodedBody();
    }
}


<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Consent\ConsentTicketSigner;
use VoltCMS\MCP\OAuth\Endpoints\AuthorizeEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\RevokeEndpoint;
use VoltCMS\MCP\OAuth\Endpoints\TokenEndpoint;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\AuthCodeRepository;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\OAuth\Repositories\RefreshTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\ScopeRepository;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;

/**
 * A whole authorization server on disk, wired the way `OAuthServer` wires one, so an endpoint test
 * exercises the real league pipeline rather than a mock of it. The tightenings this package exists
 * for only mean anything against the real thing.
 */
abstract class EndpointTestCase extends RepositoryTestCase
{
    protected const CLIENT_ID       = 'claude-desktop';
    protected const CLIENT_NAME     = 'Claude Desktop';
    protected const REDIRECT_URI    = 'https://claude.ai/callback';
    protected const CONFIDENTIAL_ID = 'server-side-client';
    protected const CLIENT_SECRET   = 'a-secret-only-the-server-and-the-client-hold';

    protected AuthorizationServer $server;
    protected ClientRepository $clients;
    protected AccessTokenRepository $accessTokens;
    protected RefreshTokenRepository $refreshTokens;

    protected AuthorizeEndpoint $authorize;
    protected TokenEndpoint $token;
    protected RevokeEndpoint $revoke;

    protected StubIdentityProvider $identities;
    protected RecordingConsentView $consentView;
    protected RecordingLoginRedirector $loginRedirector;
    protected ConsentTicketSigner $tickets;

    protected string $codeVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->clients = new ClientRepository($this->configuration);
        $this->clients->save(new Client(self::CLIENT_ID, self::CLIENT_NAME, [self::REDIRECT_URI]));
        $this->clients->save(
            new Client(self::CONFIDENTIAL_ID, 'Server Side Client', [self::REDIRECT_URI], true),
            self::CLIENT_SECRET,
        );

        $this->accessTokens  = new AccessTokenRepository($this->configuration);
        $this->refreshTokens = new RefreshTokenRepository($this->configuration);
        $authCodes           = new AuthCodeRepository($this->configuration);

        $this->server = new AuthorizationServer(
            $this->clients,
            $this->accessTokens,
            new ScopeRepository($this->configuration),
            new CryptKey(TestKeys::privateKeyPem()),
            $this->configuration->encryptionKey,
        );

        $authCodeGrant = new AuthCodeGrant(
            $authCodes,
            $this->refreshTokens,
            $this->configuration->authorizationCodeTtl,
        );
        $authCodeGrant->setRefreshTokenTTL($this->configuration->refreshTokenTtl);
        $this->server->enableGrantType($authCodeGrant, $this->configuration->accessTokenTtl);

        $refreshGrant = new RefreshTokenGrant($this->refreshTokens);
        $refreshGrant->setRefreshTokenTTL($this->configuration->refreshTokenTtl);
        $this->server->enableGrantType($refreshGrant, $this->configuration->accessTokenTtl);

        $psr = new PsrAdapter();

        $this->identities      = new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor']));
        $this->consentView     = new RecordingConsentView();
        $this->loginRedirector = new RecordingLoginRedirector();
        $this->tickets         = new ConsentTicketSigner($this->configuration->encryptionKey);

        $this->authorize = new AuthorizeEndpoint(
            $this->server,
            $this->configuration,
            $this->identities,
            new StubScopePolicy(['mcp:read', 'mcp:write']),
            $this->consentView,
            $this->loginRedirector,
            $this->tickets,
            $psr,
        );

        $this->token = new TokenEndpoint($this->server, $this->configuration, $psr);

        $this->revoke = new RevokeEndpoint(
            $this->configuration,
            $this->clients,
            $this->accessTokens,
            $this->refreshTokens,
            new AccessTokenVerifier(
                $this->configuration->issuer,
                $this->configuration->resource,
                [TestKeys::publicKeyPem()],
            ),
            $psr,
        );

        $this->codeVerifier = Pkce::verifier();
    }

    // --- Requests ---

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    protected function authorizeQuery(array $overrides = []): array
    {
        return array_filter(array_merge([
            'response_type'         => 'code',
            'client_id'             => self::CLIENT_ID,
            'redirect_uri'          => self::REDIRECT_URI,
            'scope'                 => 'mcp:read mcp:write',
            'state'                 => 'xyz',
            'code_challenge'        => $this->codeChallenge(),
            'code_challenge_method' => 'S256',
        ], $overrides), static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @param array<string, mixed> $query
     */
    protected function getAuthorize(array $query): Response
    {
        return $this->authorize->handle(new Request('GET', '/oauth/authorize?' . http_build_query($query), $query));
    }

    /**
     * @param array<string, mixed> $query
     */
    protected function postConsent(
        array $query,
        string $ticket,
        string $decision = ConsentRequest::DECISION_APPROVE,
    ): Response {
        return $this->authorize->handle(new Request(
            'POST',
            '/oauth/authorize?' . http_build_query($query),
            $query,
            [
                ConsentRequest::FIELD_TICKET   => $ticket,
                ConsentRequest::FIELD_DECISION => $decision,
            ],
        ));
    }

    /**
     * Consent screen, then approval, then the authorization code out of the redirect.
     */
    protected function approvedCode(): string
    {
        $query = $this->authorizeQuery();

        $this->getAuthorize($query);

        return $this->codeFrom($this->postConsent($query, $this->consentView->ticket()));
    }

    protected function codeFrom(Response $response): string
    {
        parse_str((string) parse_url((string) $response->header('Location'), PHP_URL_QUERY), $parameters);

        $this->assertIsString($parameters['code'] ?? null, 'The redirect carried no authorization code.');

        return $parameters['code'];
    }

    /**
     * @param array<string, mixed> $body
     */
    protected function postToken(array $body): Response
    {
        return $this->token->handle(new Request('POST', '/oauth/token', [], $body));
    }

    /**
     * @return array<string, mixed>
     */
    protected function exchange(string $code): array
    {
        return $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $code,
            'code_verifier' => $this->codeVerifier,
        ])->decodedBody();
    }

    /**
     * @return array<string, mixed>
     */
    protected function issueTokens(): array
    {
        return $this->exchange($this->approvedCode());
    }

    protected function codeChallenge(?string $verifier = null): string
    {
        return Pkce::challengeFor($verifier ?? $this->codeVerifier);
    }
}

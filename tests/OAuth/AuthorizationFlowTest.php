<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use Nyholm\Psr7\Response as Psr7Response;
use Nyholm\Psr7\ServerRequest;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Entities\User;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\AuthCodeRepository;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\OAuth\Repositories\RefreshTokenRepository;
use VoltCMS\MCP\OAuth\Repositories\ScopeRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\TestKeys;

/**
 * The repositories driven by the real league/oauth2-server pipeline, end to end.
 *
 * Unit tests prove each repository behaves; only this proves the set of them satisfies league's
 * contracts well enough to issue a token. It is also where PLAN.md §6's "inherited guarantees"
 * live: PKCE required for public clients, single-use codes, refresh rotation and exact
 * redirect_uri matching are league's implementations, but they are OUR promises, so they are
 * tested here rather than assumed.
 *
 * `testTheIssuedTokensAudienceIsTheResource` is the §4.2 tripwire at integration level: the
 * entity test proves the claim is built correctly, this proves league actually mints the entity.
 */
final class AuthorizationFlowTest extends RepositoryTestCase
{
    private const REDIRECT_URI = 'https://claude.ai/callback';

    private AuthorizationServer $server;
    private string $codeVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $clients = new ClientRepository($this->configuration);
        $clients->save(new Client('claude-desktop', 'Claude Desktop', [self::REDIRECT_URI]));

        $authCodes     = new AuthCodeRepository($this->configuration);
        $refreshTokens = new RefreshTokenRepository($this->configuration);

        $this->server = new AuthorizationServer(
            $clients,
            new AccessTokenRepository($this->configuration),
            new ScopeRepository($this->configuration),
            new CryptKey(TestKeys::privateKeyPem()),
            $this->configuration->encryptionKey,
        );

        $authCodeGrant = new AuthCodeGrant($authCodes, $refreshTokens, $this->configuration->authorizationCodeTtl);
        $authCodeGrant->setRefreshTokenTTL($this->configuration->refreshTokenTtl);
        $this->server->enableGrantType($authCodeGrant, $this->configuration->accessTokenTtl);

        $refreshGrant = new RefreshTokenGrant($refreshTokens);
        $refreshGrant->setRefreshTokenTTL($this->configuration->refreshTokenTtl);
        $this->server->enableGrantType($refreshGrant, $this->configuration->accessTokenTtl);

        $this->codeVerifier = bin2hex(random_bytes(32));
    }

    // --- The happy path ---

    public function testIssuesABearerTokenForAnApprovedAuthorizationCode(): void
    {
        $token = $this->exchange($this->authorize());

        $this->assertSame('Bearer', $token['token_type']);
    }

    public function testTheIssuedTokenLastsTheConfiguredHour(): void
    {
        $token = $this->exchange($this->authorize());

        $this->assertSame(3600, $token['expires_in']);
    }

    public function testTheIssuedTokensAudienceIsTheResource(): void
    {
        $claims = $this->claims($this->exchange($this->authorize())['access_token']);

        $this->assertSame(['https://example.com/mcp'], $claims->get('aud'));
    }

    public function testTheIssuedTokenNamesTheUserAsItsSubject(): void
    {
        $claims = $this->claims($this->exchange($this->authorize())['access_token']);

        $this->assertSame('jannis', $claims->get('sub'));
    }

    public function testTheIssuedTokenCarriesTheGrantedScopes(): void
    {
        $claims = $this->claims($this->exchange($this->authorize())['access_token']);

        $this->assertSame(['mcp:read', 'mcp:write'], $claims->get('scopes'));
    }

    // --- Inherited guarantees ---

    public function testAnAuthorizationCodeCannotBeRedeemedTwice(): void
    {
        $request = $this->tokenRequest($this->authorize());
        $this->server->respondToAccessTokenRequest($request, new Psr7Response());

        $this->expectException(OAuthServerException::class);

        $this->server->respondToAccessTokenRequest($request, new Psr7Response());
    }

    public function testARefreshTokenIsRotatedOnUse(): void
    {
        $token     = $this->exchange($this->authorize());
        $refreshed = $this->refresh($token['refresh_token']);

        $this->assertNotSame($token['refresh_token'], $refreshed['refresh_token']);
    }

    public function testASupersededRefreshTokenIsRefused(): void
    {
        $token = $this->exchange($this->authorize());
        $this->refresh($token['refresh_token']);

        $this->expectException(OAuthServerException::class);

        $this->refresh($token['refresh_token']);
    }

    public function testPkceIsRequiredForAPublicClient(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest($this->authorizeRequest(challenge: null));
    }

    public function testAForeignRedirectUriIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest(
            $this->authorizeRequest(redirectUri: 'https://attacker.example/callback'),
        );
    }

    public function testARedirectUriWithAnAddedTrailingSlashIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest(
            $this->authorizeRequest(redirectUri: self::REDIRECT_URI . '/'),
        );
    }

    public function testARedirectUriWithAnAddedQueryStringIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest(
            $this->authorizeRequest(redirectUri: self::REDIRECT_URI . '?next=/admin'),
        );
    }

    public function testARedirectUriDifferingOnlyInCaseIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest(
            $this->authorizeRequest(redirectUri: 'https://claude.ai/CALLBACK'),
        );
    }

    /**
     * The FileDB wildcard hazard, reached the way an attacker would: through the client_id
     * parameter of a real authorization request. See PLAN.md §4.8.
     */
    public function testAWildcardClientIdMatchesNoRegisteredClient(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest($this->authorizeRequest(clientId: 'claude*'));
    }

    public function testAnUnknownClientIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->server->validateAuthorizationRequest($this->authorizeRequest(clientId: 'never-registered'));
    }

    // --- Helpers ---

    private function codeChallenge(): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $this->codeVerifier, true)), '+/', '-_'), '=');
    }

    private function authorizeRequest(
        ?string $clientId = 'claude-desktop',
        ?string $redirectUri = self::REDIRECT_URI,
        ?string $challenge = 'default',
    ): ServerRequest {
        $query = [
            'response_type' => 'code',
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUri,
            'scope'         => 'mcp:read mcp:write',
            'state'         => 'xyz',
        ];

        if ($challenge !== null) {
            $query['code_challenge']        = $challenge === 'default' ? $this->codeChallenge() : $challenge;
            $query['code_challenge_method'] = 'S256';
        }

        return (new ServerRequest('GET', 'https://example.com/authorize'))->withQueryParams($query);
    }

    /**
     * Runs authorize through to the redirect and returns the authorization code.
     */
    private function authorize(): string
    {
        $authRequest = $this->server->validateAuthorizationRequest($this->authorizeRequest());
        $authRequest->setUser(new User('jannis'));
        $authRequest->setAuthorizationApproved(true);

        $location = $this->server
            ->completeAuthorizationRequest($authRequest, new Psr7Response())
            ->getHeaderLine('Location');

        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);

        $this->assertSame('xyz', $query['state'] ?? null);
        $this->assertIsString($query['code'] ?? null);

        return $query['code'];
    }

    private function tokenRequest(string $code): ServerRequest
    {
        return (new ServerRequest('POST', 'https://example.com/token'))->withParsedBody([
            'grant_type'    => 'authorization_code',
            'client_id'     => 'claude-desktop',
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $code,
            'code_verifier' => $this->codeVerifier,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function exchange(string $code): array
    {
        $response = $this->server->respondToAccessTokenRequest($this->tokenRequest($code), new Psr7Response());

        return (array) json_decode((string) $response->getBody(), true);
    }

    /**
     * @return array<string, mixed>
     */
    private function refresh(string $refreshToken): array
    {
        $request = (new ServerRequest('POST', 'https://example.com/token'))->withParsedBody([
            'grant_type'    => 'refresh_token',
            'client_id'     => 'claude-desktop',
            'refresh_token' => $refreshToken,
            'scope'         => 'mcp:read mcp:write',
        ]);

        $response = $this->server->respondToAccessTokenRequest($request, new Psr7Response());

        return (array) json_decode((string) $response->getBody(), true);
    }

    private function claims(string $jwt): \Lcobucci\JWT\Token\DataSet
    {
        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertInstanceOf(UnencryptedToken::class, $parsed);

        return $parsed->claims();
    }
}

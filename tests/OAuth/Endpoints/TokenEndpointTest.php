<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;

/**
 * The token endpoint, driven through the same authorize endpoint a client would use.
 *
 * `testTheIssuedTokensAudienceIsTheResource` is the §4.2 tripwire at endpoint level: the entity
 * test proves the claim is built correctly and `AuthorizationFlowTest` proves league mints the
 * entity, and this proves the endpoint a client actually posts to returns that token and no other.
 *
 * The inherited guarantees — single-use codes, refresh rotation, PKCE verification — are league's
 * implementations tested here because PLAN.md §4.7 says they are our promises.
 */
final class TokenEndpointTest extends EndpointTestCase
{
    // --- The happy path ---

    public function testExchangesAnApprovedCodeForABearerToken(): void
    {
        $this->assertSame('Bearer', $this->issueTokens()['token_type'] ?? null);
    }

    public function testTheIssuedTokenLastsTheConfiguredHour(): void
    {
        $this->assertSame(3600, $this->issueTokens()['expires_in'] ?? null);
    }

    public function testTheIssuedTokensAudienceIsTheResource(): void
    {
        $claims = $this->claims((string) $this->issueTokens()['access_token']);

        $this->assertSame(['https://example.com/mcp'], $claims->get('aud'));
    }

    public function testTheIssuedTokenNamesTheApprovingUserAsItsSubject(): void
    {
        $claims = $this->claims((string) $this->issueTokens()['access_token']);

        $this->assertSame('jannis', $claims->get('sub'));
    }

    public function testTheIssuedTokenCarriesOnlyTheGrantedScopes(): void
    {
        $claims = $this->claims((string) $this->issueTokens()['access_token']);

        $this->assertSame(['mcp:read', 'mcp:write'], $claims->get('scopes'));
    }

    public function testTheResponseIsNotCacheable(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
        ]);

        $this->assertSame('no-store', $response->header('cache-control'));
    }

    // --- Inherited guarantees ---

    public function testAnAuthorizationCodeCannotBeRedeemedTwice(): void
    {
        $code = $this->approvedCode();
        $this->exchange($code);

        $this->assertSame('invalid_grant', $this->exchange($code)['error'] ?? null);
    }

    public function testACodeVerifierThatDoesNotMatchTheChallengeIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => bin2hex(random_bytes(32)),
        ]);

        $this->assertSame('invalid_grant', $response->decodedBody()['error'] ?? null);
    }

    public function testAMissingCodeVerifierIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'   => 'authorization_code',
            'client_id'    => self::CLIENT_ID,
            'redirect_uri' => self::REDIRECT_URI,
            'code'         => $this->approvedCode(),
        ]);

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testARedirectUriThatDiffersFromTheOneInTheCodeIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI . '/',
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
        ]);

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testARefreshTokenIsRotatedOnUse(): void
    {
        $issued    = $this->issueTokens();
        $refreshed = $this->refresh((string) $issued['refresh_token']);

        $this->assertNotSame($issued['refresh_token'], $refreshed['refresh_token'] ?? null);
    }

    public function testASupersededRefreshTokenIsRefused(): void
    {
        $issued = $this->issueTokens();
        $this->refresh((string) $issued['refresh_token']);

        $this->assertSame('invalid_grant', $this->refresh((string) $issued['refresh_token'])['error'] ?? null);
    }

    public function testAnotherClientsCodeIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CONFIDENTIAL_ID,
            'client_secret' => self::CLIENT_SECRET,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
        ]);

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testAConfidentialClientWithTheWrongSecretIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CONFIDENTIAL_ID,
            'client_secret' => 'not-the-secret',
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
        ]);

        $this->assertSame('invalid_client', $response->decodedBody()['error'] ?? null);
    }

    // --- RFC 8707 ---

    public function testAResourceParameterNamingAnotherServerIsRefused(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
            'resource'      => 'https://attacker.example/mcp',
        ]);

        $this->assertSame('invalid_target', $response->decodedBody()['error'] ?? null);
    }

    public function testAResourceParameterNamingThisServerIsAccepted(): void
    {
        $response = $this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $this->approvedCode(),
            'code_verifier' => $this->codeVerifier,
            'resource'      => 'https://example.com/mcp',
        ]);

        $this->assertSame('Bearer', $response->decodedBody()['token_type'] ?? null);
    }

    // --- The frame ---

    public function testAGetIsRefusedWithTheAllowedMethod(): void
    {
        $response = $this->token->handle(new Request('GET', '/oauth/token'));

        $this->assertSame(Response::STATUS_METHOD_NOT_ALLOWED, $response->status);
        $this->assertSame('POST', $response->header('Allow'));
    }

    public function testNothingIsWrittenToTheOutputBuffer(): void
    {
        $code = $this->approvedCode();

        ob_start();
        $this->exchange($code);
        $emitted = (string) ob_get_clean();

        $this->assertSame('', $emitted);
    }

    // --- Helpers ---

    /**
     * @return array<string, mixed>
     */
    private function refresh(string $refreshToken): array
    {
        return $this->postToken([
            'grant_type'    => 'refresh_token',
            'client_id'     => self::CLIENT_ID,
            'refresh_token' => $refreshToken,
            'scope'         => 'mcp:read mcp:write',
        ])->decodedBody();
    }

    private function claims(string $jwt): DataSet
    {
        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertInstanceOf(UnencryptedToken::class, $parsed);

        return $parsed->claims();
    }
}

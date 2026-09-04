<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Endpoints\MetadataEndpoint;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuthServer;
use VoltCMS\MCP\Tests\Support\RecordingConsentView;
use VoltCMS\MCP\Tests\Support\RecordingLoginRedirector;
use VoltCMS\MCP\Tests\Support\Pkce;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;

/**
 * The façade, assembled exactly as a consuming application assembles it, and driven the whole way:
 * discovery, authorize, consent, exchange, verify, revoke.
 *
 * Every guarantee below is tested somewhere else too, against the class that implements it. What
 * this proves is the wiring — that the endpoints, the repositories, the two grants and the keypair
 * were connected to each other and not to something else. It is the only test in the suite that
 * would fail if the façade handed the token endpoint a different storage directory, or built the
 * verifier against a key the server does not sign with.
 */
final class OAuthServerTest extends RepositoryTestCase
{
    private const CLIENT_ID    = 'claude-desktop';
    private const REDIRECT_URI = 'https://claude.ai/callback';

    private OAuthServer $oauth;
    private RecordingConsentView $consentView;
    private RecordingLoginRedirector $loginRedirector;
    private string $codeVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->consentView     = new RecordingConsentView();
        $this->loginRedirector = new RecordingLoginRedirector();
        $this->codeVerifier    = Pkce::verifier();

        $this->oauth = new OAuthServer(
            $this->configuration,
            new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            new StubScopePolicy(['mcp:read', 'mcp:write']),
            $this->consentView,
            $this->loginRedirector,
        );

        $this->oauth->clients()->save(new Client(self::CLIENT_ID, 'Claude Desktop', [self::REDIRECT_URI]));
    }

    // --- Assembly ---

    public function testGeneratesItsKeypairOnConstruction(): void
    {
        $this->assertFileExists($this->configuration->privateKeyPath);
    }

    public function testPublishesMetadataNamingItsOwnEndpoints(): void
    {
        $document = $this->oauth->metadata(new Request('GET', MetadataEndpoint::WELL_KNOWN_PATH))->decodedBody();

        $this->assertSame($this->configuration->tokenEndpoint, $document['token_endpoint']);
    }

    public function testPublishesAJwksContainingTheKeyItSignsWith(): void
    {
        $document = $this->oauth->jwks(new Request('GET', '/oauth/jwks'))->decodedBody();

        $this->assertSame($this->oauth->keys()->keyId(), $document['keys'][0]['kid']);
    }

    // --- The whole flow ---

    public function testIssuesATokenForAnApprovedAuthorizationRequest(): void
    {
        $this->assertSame('Bearer', $this->issue()['token_type'] ?? null);
    }

    public function testTheIssuedTokenNamesTheKeyItWasSignedWith(): void
    {
        $token = (new Parser(new JoseEncoder()))->parse((string) $this->issue()['access_token']);

        $this->assertInstanceOf(UnencryptedToken::class, $token);
        $this->assertSame($this->oauth->keys()->keyId(), $token->headers()->get('kid'));
    }

    public function testTheIssuedTokenVerifiesAgainstTheServersOwnVerifier(): void
    {
        $claims = $this->oauth->accessTokenVerifier()->verify((string) $this->issue()['access_token']);

        $this->assertSame('jannis', $claims?->subject);
    }

    public function testTheIssuedTokenStillVerifiesAfterAKeyRotation(): void
    {
        $token = (string) $this->issue()['access_token'];

        $this->oauth->keys()->rotate();

        $this->assertNotNull($this->oauth->accessTokenVerifier()->verify($token));
    }

    public function testRevokingEndsTheGrant(): void
    {
        $issued = $this->issue();

        $this->oauth->revoke(new Request('POST', '/oauth/revoke', [], [
            'token'     => $issued['refresh_token'],
            'client_id' => self::CLIENT_ID,
        ]));

        $refreshed = $this->oauth->token(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'refresh_token',
            'client_id'     => self::CLIENT_ID,
            'refresh_token' => $issued['refresh_token'],
        ]))->decodedBody();

        $this->assertSame('invalid_grant', $refreshed['error'] ?? null);
    }

    public function testAnUnauthenticatedVisitorIsSentToTheApplicationsLoginPage(): void
    {
        $oauth = new OAuthServer(
            $this->configuration,
            new StubIdentityProvider(null),
            new StubScopePolicy(['mcp:read']),
            $this->consentView,
            $this->loginRedirector,
        );

        $response = $oauth->authorize($this->authorizeRequest('GET'));

        $this->assertSame(Response::STATUS_FOUND, $response->status);
        $this->assertSame(1, $this->loginRedirector->redirectCount);
    }

    // --- Housekeeping ---

    public function testPurgesExpiredRecordsAcrossEveryCollection(): void
    {
        $this->issue();

        $this->assertGreaterThan(0, $this->oauth->purgeExpired(new \DateTimeImmutable('+40 days')));
    }

    public function testPurgingLeavesLiveRecordsAlone(): void
    {
        $this->issue();

        $this->assertSame(0, $this->oauth->purgeExpired());
    }

    // --- Helpers ---

    /**
     * @return array<string, mixed>
     */
    private function issue(): array
    {
        $this->oauth->authorize($this->authorizeRequest('GET'));

        $redirect = $this->oauth->authorize($this->authorizeRequest('POST', [
            ConsentRequest::FIELD_TICKET   => $this->consentView->ticket(),
            ConsentRequest::FIELD_DECISION => ConsentRequest::DECISION_APPROVE,
        ]));

        parse_str((string) parse_url((string) $redirect->header('Location'), PHP_URL_QUERY), $parameters);

        $this->assertIsString($parameters['code'] ?? null, 'The redirect carried no authorization code.');

        return $this->oauth->token(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_ID,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $parameters['code'],
            'code_verifier' => $this->codeVerifier,
        ]))->decodedBody();
    }

    /**
     * @param array<string, mixed> $body
     */
    private function authorizeRequest(string $method, array $body = []): Request
    {
        $query = [
            'response_type'         => 'code',
            'client_id'             => self::CLIENT_ID,
            'redirect_uri'          => self::REDIRECT_URI,
            'scope'                 => 'mcp:read mcp:write',
            'state'                 => 'xyz',
            'code_challenge'        => Pkce::challengeFor($this->codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        return new Request($method, '/oauth/authorize?' . http_build_query($query), $query, $body);
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Clients;

use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuthServer;
use VoltCMS\MCP\Tests\Support\RecordingConsentView;
use VoltCMS\MCP\Tests\Support\RecordingLoginRedirector;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\StubClientIdMetadataFetcher;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;

/**
 * A client this server has never met, all the way through: a `client_id` that is a URL, resolved by
 * fetching the document there, consented to, and exchanged for a token.
 *
 * This is what makes dynamic registration unnecessary here, and therefore what lets registration be
 * off by default. See docs/decisions/0006-who-answers-registration.md.
 */
final class ClientIdMetadataFlowTest extends RepositoryTestCase
{
    private const CLIENT_URL   = 'https://claude.ai/client.json';
    private const REDIRECT_URI = 'https://claude.ai/callback';

    private OAuthServer $oauth;
    private RecordingConsentView $consentView;
    private StubClientIdMetadataFetcher $fetcher;
    private string $codeVerifier;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new StubClientIdMetadataFetcher();
        $this->fetcher->serve(self::CLIENT_URL, [
            'client_id'     => self::CLIENT_URL,
            'client_name'   => 'Claude Desktop',
            'redirect_uris' => [self::REDIRECT_URI],
        ]);

        $this->consentView  = new RecordingConsentView();
        $this->codeVerifier = bin2hex(random_bytes(32));

        $this->oauth = new OAuthServer(
            $this->configuration,
            new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            new StubScopePolicy(['mcp:read', 'mcp:write']),
            $this->consentView,
            new RecordingLoginRedirector(),
            clientMetadataFetcher: $this->fetcher,
        );
    }

    public function testAnUnregisteredClientIdentifiedByItsDocumentReachesTheConsentScreen(): void
    {
        $this->oauth->authorize($this->authorize('GET'));

        $this->assertSame(1, $this->consentView->renderCount);
    }

    public function testTheConsentScreenShowsTheNameTheDocumentGave(): void
    {
        $this->oauth->authorize($this->authorize('GET'));

        $this->assertSame('Claude Desktop', $this->consentView->lastRequest?->clientName);
    }

    public function testTheWholeFlowIssuesATokenToADocumentIdentifiedClient(): void
    {
        $this->assertSame('Bearer', $this->issue()['token_type'] ?? null);
    }

    public function testTheIssuedTokenNamesTheDocumentUrlAsItsClient(): void
    {
        $claims = $this->oauth->accessTokenVerifier()->verify((string) $this->issue()['access_token']);

        $this->assertSame(self::CLIENT_URL, $claims?->clientId);
    }

    /**
     * The document lists one redirect URI, so league must refuse any other — the same exact match
     * a registered client gets, from a registration nobody performed.
     */
    public function testARedirectUriTheDocumentDoesNotListIsRefused(): void
    {
        $response = $this->oauth->authorize($this->authorize('GET', ['redirect_uri' => 'https://attacker.example/cb']));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testADocumentUrlThatServesNothingIsNotAClient(): void
    {
        $response = $this->oauth->authorize(
            $this->authorize('GET', ['client_id' => 'https://nowhere.example/client.json']),
        );

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    /**
     * A deactivated client cannot re-admit itself by serving a document: the stored record is
     * consulted first and its refusal is final.
     */
    public function testADeactivatedClientCannotComeBackThroughItsDocument(): void
    {
        $this->oauth->clients()->save(new Client(self::CLIENT_URL, 'Claude Desktop', [self::REDIRECT_URI]));
        $this->oauth->clients()->deactivate(self::CLIENT_URL);

        $response = $this->oauth->authorize($this->authorize('GET'));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testADocumentIdentifiedClientCannotPresentASecret(): void
    {
        $this->assertFalse($this->oauth->clients()->validateClient(self::CLIENT_URL, 'invented', null));
    }

    // --- Helpers ---

    /**
     * @return array<string, mixed>
     */
    private function issue(): array
    {
        $query = $this->authorizeQuery();

        $this->oauth->authorize($this->authorize('GET'));

        $redirect = $this->oauth->authorize(new Request(
            'POST',
            '/oauth/authorize?' . http_build_query($query),
            $query,
            [
                ConsentRequest::FIELD_TICKET   => $this->consentView->ticket(),
                ConsentRequest::FIELD_DECISION => ConsentRequest::DECISION_APPROVE,
            ],
        ));

        parse_str((string) parse_url((string) $redirect->header('Location'), PHP_URL_QUERY), $parameters);

        $this->assertIsString($parameters['code'] ?? null, 'The redirect carried no authorization code.');

        return $this->oauth->token(new Request('POST', '/oauth/token', [], [
            'grant_type'    => 'authorization_code',
            'client_id'     => self::CLIENT_URL,
            'redirect_uri'  => self::REDIRECT_URI,
            'code'          => $parameters['code'],
            'code_verifier' => $this->codeVerifier,
        ]))->decodedBody();
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function authorize(string $method, array $overrides = []): Request
    {
        $query = $this->authorizeQuery($overrides);

        return new Request($method, '/oauth/authorize?' . http_build_query($query), $query);
    }

    /**
     * @param array<string, mixed> $overrides
     *
     * @return array<string, mixed>
     */
    private function authorizeQuery(array $overrides = []): array
    {
        return array_merge([
            'response_type'         => 'code',
            'client_id'             => self::CLIENT_URL,
            'redirect_uri'          => self::REDIRECT_URI,
            'scope'                 => 'mcp:read mcp:write',
            'state'                 => 'xyz',
            'code_challenge'        => rtrim(strtr(base64_encode(hash('sha256', $this->codeVerifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ], $overrides);
    }
}

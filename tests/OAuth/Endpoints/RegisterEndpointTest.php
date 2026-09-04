<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Clients\ManualRegistration;
use VoltCMS\MCP\OAuth\Endpoints\RegisterEndpoint;
use VoltCMS\MCP\OAuth\Repositories\ClientRepository;
use VoltCMS\MCP\OAuthServer;
use VoltCMS\MCP\Tests\Support\RecordingConsentView;
use VoltCMS\MCP\Tests\Support\RecordingLoginRedirector;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;

/**
 * RFC 7591 registration, and the fact that it is off unless asked for.
 *
 * The default matters more than the endpoint does. An open registration endpoint is an
 * unauthenticated write endpoint on a personal site's credential store, and Client ID Metadata
 * Documents do the same job without one — so the two tests about a server that did NOT ask for it
 * are the ones guarding the decision. See docs/decisions/0006-who-answers-registration.md.
 */
final class RegisterEndpointTest extends RepositoryTestCase
{
    // --- Off by default ---

    public function testAServerThatDidNotAskForRegistrationAnswersAsIfItHasNoSuchEndpoint(): void
    {
        $response = $this->oauth($this->configuration)->register($this->registration());

        $this->assertSame(Response::STATUS_NOT_FOUND, $response->status);
    }

    public function testAServerThatDidNotAskForRegistrationRegistersNothing(): void
    {
        $oauth = $this->oauth($this->configuration);
        $oauth->register($this->registration());

        $this->assertSame([], glob($this->storageDirectory . '/clients/*.json') ?: []);
    }

    // --- On, when asked for ---

    public function testRegistersAClientAndReturnsItsIdentifier(): void
    {
        $response = $this->endpoint()->handle($this->registration());

        $this->assertSame(RegisterEndpoint::STATUS_CREATED, $response->status);
        $this->assertIsString($response->decodedBody()['client_id'] ?? null);
    }

    public function testTheRegisteredClientCanThenBeFound(): void
    {
        $response = $this->endpoint()->handle($this->registration());
        $clientId = (string) $response->decodedBody()['client_id'];

        $this->assertNotNull((new ClientRepository($this->configuration))->getClientEntity($clientId));
    }

    public function testTheRegisteredClientIsPublicAndHoldsNoSecret(): void
    {
        $response = $this->endpoint()->handle($this->registration());

        $this->assertSame('none', $response->decodedBody()['token_endpoint_auth_method'] ?? null);
        $this->assertArrayNotHasKey('client_secret', $response->decodedBody());
    }

    public function testEchoesTheRedirectUrisItAccepted(): void
    {
        $response = $this->endpoint()->handle($this->registration());

        $this->assertSame(['https://claude.ai/callback'], $response->decodedBody()['redirect_uris'] ?? null);
    }

    // --- Refusals ---

    public function testRefusesARegistrationWithNoRedirectUris(): void
    {
        $response = $this->endpoint()->handle($this->registration(['redirect_uris' => null]));

        $this->assertSame(Response::STATUS_BAD_REQUEST, $response->status);
        $this->assertSame(RegisterEndpoint::ERROR_INVALID_METADATA, $response->decodedBody()['error'] ?? null);
    }

    public function testRefusesAPlainHttpRedirectUri(): void
    {
        $response = $this->endpoint()->handle($this->registration(['redirect_uris' => ['http://claude.ai/callback']]));

        $this->assertSame(Response::STATUS_BAD_REQUEST, $response->status);
    }

    public function testRefusesABodyThatIsNotJson(): void
    {
        $endpoint = $this->endpoint();
        $response = $endpoint->handle(new Request('POST', '/oauth/register', [], [], [], '', 'not json'));

        $this->assertSame(Response::STATUS_BAD_REQUEST, $response->status);
    }

    public function testAGetIsRefusedWithTheAllowedMethod(): void
    {
        $response = $this->endpoint()->handle(new Request('GET', '/oauth/register'));

        $this->assertSame(Response::STATUS_METHOD_NOT_ALLOWED, $response->status);
        $this->assertSame('POST', $response->header('Allow'));
    }

    // --- Helpers ---

    private function endpoint(): RegisterEndpoint
    {
        return new RegisterEndpoint(
            $this->configuration,
            new ManualRegistration(new ClientRepository($this->configuration)),
            new PsrAdapter(),
        );
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function registration(array $overrides = []): Request
    {
        $body = array_merge([
            'client_name'   => 'Claude Desktop',
            'redirect_uris' => ['https://claude.ai/callback'],
        ], $overrides);

        if (array_key_exists('redirect_uris', $overrides) && $overrides['redirect_uris'] === null) {
            unset($body['redirect_uris']);
        }

        return new Request(
            'POST',
            '/oauth/register',
            [],
            [],
            ['Content-Type' => 'application/json'],
            '203.0.113.4',
            (string) json_encode($body),
        );
    }

    private function oauth(Configuration $configuration): OAuthServer
    {
        return new OAuthServer(
            $configuration,
            new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            new StubScopePolicy(['mcp:read']),
            new RecordingConsentView(),
            new RecordingLoginRedirector(),
        );
    }
}

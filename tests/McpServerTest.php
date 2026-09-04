<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests;

use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\McpServer;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;
use VoltCMS\MCP\Tests\Support\TestKeys;

/**
 * The MCP endpoint, driven with tokens this package's own authorization server issued.
 *
 * This is the test the whole repository is for. Everything else proves a piece; this proves the
 * two halves meet — that `mcp/sdk` accepts a token `league/oauth2-server` minted, through a
 * validator that reads a key off disk and never touches the network.
 *
 * No network, and no `firebase/php-jwt`: the SDK's own `JwtTokenValidator` would need both, which
 * is why `McpTokenValidator` exists.
 */
final class McpServerTest extends EndpointTestCase
{
    private const PROTOCOL_VERSION = '2025-06-18';

    public function testRefusesARequestWithNoToken(): void
    {
        $response = $this->mcp()->handle($this->initialize());

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    /**
     * RFC 9728: the challenge tells the client where to find the resource metadata, and from there
     * the authorization server. The authority is the configured one, never the request's — which is
     * why the endpoint URL handed to the transport comes from Configuration.
     */
    public function testTheChallengePointsAtTheConfiguredResourceMetadata(): void
    {
        $response = $this->mcp()->handle($this->initialize());

        $this->assertStringContainsString(
            'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"',
            (string) $response->header('WWW-Authenticate'),
        );
    }

    /**
     * `mcp/sdk`'s DNS-rebinding protection defaults to an allowlist of localhost variants, which
     * would 403 every request to a deployed server. `McpServer` rebuilds it around the configured
     * resource host instead — so a legitimate `Host` passes and a forged one still does not.
     */
    public function testAForeignHostHeaderIsRefusedBeforeAnythingElse(): void
    {
        $response = $this->mcp()->handle($this->initialize(token: $this->accessToken(), host: 'attacker.example'));

        $this->assertSame(403, $response->status);
    }

    public function testRefusesAMalformedAuthorizationHeader(): void
    {
        $request  = $this->initialize(headers: ['Authorization' => 'Bearer']);
        $response = $this->mcp()->handle($request);

        $this->assertSame(Response::STATUS_BAD_REQUEST, $response->status);
    }

    public function testRefusesAForgedToken(): void
    {
        $response = $this->mcp()->handle($this->initialize(token: 'not.a.token'));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testAcceptsATokenTheAuthorizationServerIssued(): void
    {
        $response = $this->mcp()->handle($this->initialize(token: $this->accessToken()));

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    public function testCompletesTheHandshakeAndNamesItself(): void
    {
        $response = $this->mcp()->handle($this->initialize(token: $this->accessToken()));

        $this->assertSame('voltcms-mcp', $response->decodedBody()['result']['serverInfo']['name'] ?? null);
    }

    public function testCallsARegisteredTool(): void
    {
        $mcp   = $this->mcp();
        $token = $this->accessToken();

        $session = $mcp->handle($this->initialize(token: $token))->header('Mcp-Session-Id');

        $response = $mcp->handle($this->rpc([
            'jsonrpc' => '2.0',
            'id'      => 2,
            'method'  => 'tools/call',
            'params'  => ['name' => 'echo', 'arguments' => ['text' => 'hello']],
        ], token: $token, session: (string) $session));

        $this->assertSame('hello', $response->decodedBody()['result']['content'][0]['text'] ?? null);
    }

    public function testARevokedTokenStopsCallingTools(): void
    {
        $mcp   = $this->mcp();
        $token = $this->accessToken();

        $mcp->handle($this->initialize(token: $token));

        $claims = $mcp->tokenValidator()->validate($token)->getAttributes();
        $this->accessTokens->revokeAccessToken((string) $claims['oauth.token_id']);

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $mcp->handle($this->initialize(token: $token))->status);
    }

    public function testRefusesATokenWithoutARequiredScope(): void
    {
        $mcp = $this->mcp(requiredScopes: ['mcp:admin']);

        $this->assertSame(403, $mcp->handle($this->initialize(token: $this->accessToken()))->status);
    }

    // --- The RFC 9728 document ---

    public function testPublishesProtectedResourceMetadataNamingItsAuthorizationServer(): void
    {
        $document = $this->mcp()->resourceMetadata()->decodedBody();

        $this->assertSame(['https://example.com'], $document['authorization_servers'] ?? null);
    }

    public function testTheResourceMetadataNamesThisResource(): void
    {
        $document = $this->mcp()->resourceMetadata()->decodedBody();

        $this->assertSame('https://example.com/mcp', $document['resource'] ?? null);
    }

    /**
     * RFC 9728 §3.1: the resource's path is inserted after the well-known segment. This is the URL
     * the challenge advertises, so it is the one a conforming client fetches first — and the one
     * that used to 404.
     */
    public function testTheResourceMetadataPathIsTheOneInTheChallenge(): void
    {
        $this->assertSame('/.well-known/oauth-protected-resource/mcp', $this->mcp()->resourceMetadataPath());
    }

    public function testTheDocumentIsAlsoOfferedAtTheBareWellKnownPath(): void
    {
        $this->assertSame([
            '/.well-known/oauth-protected-resource/mcp',
            '/.well-known/oauth-protected-resource',
        ], $this->mcp()->resourceMetadataPaths());
    }

    /**
     * The challenge is only useful if what it points at is actually routed. This is the pairing the
     * front controller has to get right, asserted here so a change to either side breaks a test
     * rather than a client.
     */
    public function testTheChallengeUrlIsOneOfTheRoutedPaths(): void
    {
        $mcp      = $this->mcp();
        $response = $mcp->handle($this->initialize());

        $challenge = (string) $response->header('WWW-Authenticate');
        $advertised = (string) parse_url(
            (string) preg_replace('/^.*resource_metadata="([^"]+)".*$/s', '$1', $challenge),
            PHP_URL_PATH,
        );

        $this->assertContains($advertised, $mcp->resourceMetadataPaths());
    }

    public function testNothingIsWrittenToTheOutputBuffer(): void
    {
        $token = $this->accessToken();

        ob_start();
        $this->mcp()->handle($this->initialize(token: $token));
        $emitted = (string) ob_get_clean();

        $this->assertSame('', $emitted);
    }

    // --- Helpers ---

    /**
     * @param list<string> $requiredScopes
     */
    private function mcp(array $requiredScopes = []): McpServer
    {
        $mcp = new McpServer(
            $this->configuration,
            new StubIdentityProvider(new Identity('jannis', 'Jannis', ['editor'])),
            new StubScopePolicy(['mcp:read', 'mcp:write']),
            new AccessTokenVerifier(
                $this->configuration->issuer,
                $this->configuration->resource,
                [TestKeys::publicKeyPem()],
            ),
            $this->accessTokens,
            $requiredScopes,
        );

        $mcp->addTool(
            static fn (string $text): string => $text,
            name: 'echo',
            description: 'Returns what it was given.',
        );

        return $mcp;
    }

    private function accessToken(): string
    {
        return (string) $this->issueTokens()['access_token'];
    }

    /**
     * @param array<string, string> $headers
     */
    private function initialize(?string $token = null, string $host = 'example.com', array $headers = []): Request
    {
        return $this->rpc([
            'jsonrpc' => '2.0',
            'id'      => 1,
            'method'  => 'initialize',
            'params'  => [
                'protocolVersion' => self::PROTOCOL_VERSION,
                'capabilities'    => [],
                'clientInfo'      => ['name' => 'test-client', 'version' => '1.0'],
            ],
        ], $token, host: $host, headers: $headers);
    }

    /**
     * @param array<string, mixed>  $payload
     * @param array<string, string> $headers
     */
    private function rpc(
        array $payload,
        ?string $token = null,
        string $session = '',
        string $host = 'example.com',
        array $headers = [],
    ): Request {
        $headers = array_merge([
            'Host'         => $host,
            'Content-Type' => 'application/json',
            'Accept'       => 'application/json, text/event-stream',
        ], $headers);

        if ($token !== null && !isset($headers['Authorization'])) {
            $headers['Authorization'] = 'Bearer ' . $token;
        }

        if ($session !== '') {
            $headers['Mcp-Session-Id'] = $session;
        }

        return new Request(
            'POST',
            '/mcp',
            [],
            [],
            $headers,
            '203.0.113.4',
            (string) json_encode($payload),
        );
    }
}

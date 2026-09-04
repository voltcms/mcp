<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Endpoints\MetadataEndpoint;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * The RFC 8414 document, asserted whole.
 *
 * PLAN.md §6 asks for it byte-stable and free of any header-derived value, and both are checked
 * here: the first because a client caches this and a field that appears and disappears between
 * requests is a bug nobody will find, the second because a metadata document built from
 * `$_SERVER['HTTP_HOST']` publishes an attacker's origin as this application's authorization
 * server. The request the endpoint is handed below carries a hostile `Host`; none of it reaches
 * the document.
 */
final class MetadataEndpointTest extends RepositoryTestCase
{
    public function testPublishesTheWholeDocument(): void
    {
        $this->assertSame([
            'issuer'                                     => 'https://example.com',
            'authorization_endpoint'                     => 'https://example.com/oauth/authorize',
            'token_endpoint'                             => 'https://example.com/oauth/token',
            'jwks_uri'                                   => 'https://example.com/oauth/jwks',
            'revocation_endpoint'                        => 'https://example.com/oauth/revoke',
            'scopes_supported'                           => ['mcp:read', 'mcp:write'],
            'response_types_supported'                   => ['code'],
            'response_modes_supported'                   => ['query'],
            'grant_types_supported'                      => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_methods_supported'      => ['none', 'client_secret_basic', 'client_secret_post'],
            'revocation_endpoint_auth_methods_supported' => ['none', 'client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported'           => ['S256'],
            'registration_endpoint'                      => 'https://example.com/oauth/register',
        ], $this->endpoint()->handle($this->get())->decodedBody());
    }

    /**
     * The §4.1 tightening, made visible before a client sends anything.
     */
    public function testOffersS256AndNothingElse(): void
    {
        $document = $this->endpoint()->handle($this->get())->decodedBody();

        $this->assertSame(['S256'], $document['code_challenge_methods_supported']);
    }

    public function testNoValueIsTakenFromTheRequest(): void
    {
        $body = $this->endpoint()->handle($this->get())->body;

        $this->assertStringNotContainsString('attacker.example', $body);
    }

    public function testTheDocumentIsByteStableAcrossRequests(): void
    {
        $endpoint = $this->endpoint();

        $this->assertSame($endpoint->handle($this->get())->body, $endpoint->handle($this->get())->body);
    }

    public function testTheDocumentIsCacheable(): void
    {
        $response = $this->endpoint()->handle($this->get());

        $this->assertSame('public, max-age=3600', $response->header('Cache-Control'));
    }

    public function testAPostIsRefusedWithTheAllowedMethod(): void
    {
        $response = $this->endpoint()->handle(new Request('POST', MetadataEndpoint::WELL_KNOWN_PATH));

        $this->assertSame(Response::STATUS_METHOD_NOT_ALLOWED, $response->status);
        $this->assertSame('GET', $response->header('Allow'));
    }

    // --- Helpers ---

    private function endpoint(): MetadataEndpoint
    {
        return new MetadataEndpoint($this->configuration, new PsrAdapter());
    }

    private function get(): Request
    {
        return new Request('GET', MetadataEndpoint::WELL_KNOWN_PATH, [], [], ['Host' => 'attacker.example']);
    }
}

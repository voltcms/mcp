<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Keys;

use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Keys\JwksEndpoint;
use VoltCMS\MCP\OAuth\Keys\KeyManager;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * The JWKS a client fetches to verify a token this server signed. Public material only — the test
 * that says so is the one worth keeping.
 */
final class JwksEndpointTest extends RepositoryTestCase
{
    public function testPublishesTheCurrentKey(): void
    {
        $keys = new KeyManager($this->configuration);

        $document = $this->endpoint($keys)->handle($this->get())->decodedBody();

        $this->assertSame($keys->keyId(), $document['keys'][0]['kid'] ?? null);
    }

    public function testPublishesNoPrivateMaterial(): void
    {
        $body = $this->endpoint()->handle($this->get())->body;

        $this->assertStringNotContainsString('PRIVATE KEY', $body);
        $this->assertStringNotContainsString('"d"', $body);
    }

    public function testPublishesARetiredKeyAlongsideTheCurrentOne(): void
    {
        $keys = new KeyManager($this->configuration);
        $keys->ensureKeyPair();
        $keys->rotate();

        $document = $this->endpoint($keys)->handle($this->get())->decodedBody();

        $this->assertCount(2, $document['keys']);
    }

    public function testTheDocumentIsCacheable(): void
    {
        $this->assertSame('public, max-age=600', $this->endpoint()->handle($this->get())->header('Cache-Control'));
    }

    public function testAPostIsRefusedWithTheAllowedMethod(): void
    {
        $response = $this->endpoint()->handle(new Request('POST', '/oauth/jwks'));

        $this->assertSame(Response::STATUS_METHOD_NOT_ALLOWED, $response->status);
        $this->assertSame('GET', $response->header('Allow'));
    }

    private function endpoint(?KeyManager $keys = null): JwksEndpoint
    {
        return new JwksEndpoint($this->configuration, $keys ?? new KeyManager($this->configuration), new PsrAdapter());
    }

    private function get(): Request
    {
        return new Request('GET', '/oauth/jwks');
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Bridge;

use VoltCMS\MCP\Bridge\ProtectedResourceMetadata;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * The RFC 9728 document `mcp/sdk` builds and this package fills in.
 *
 * It is how a client discovers which authorization server to talk to, so the one thing that must
 * never come from the request is the authorization server — a value taken from a forged `Host`
 * would send the entire authorization flow somewhere else.
 */
final class ProtectedResourceMetadataTest extends RepositoryTestCase
{
    public function testNamesTheConfiguredIssuerAsTheAuthorizationServer(): void
    {
        $document = ProtectedResourceMetadata::forConfiguration($this->configuration)->jsonSerialize();

        $this->assertSame(['https://example.com'], $document['authorization_servers']);
    }

    public function testNamesTheConfiguredResource(): void
    {
        $document = ProtectedResourceMetadata::forConfiguration($this->configuration)->jsonSerialize();

        $this->assertSame('https://example.com/mcp', $document['resource']);
    }

    public function testPublishesTheConfiguredScopes(): void
    {
        $document = ProtectedResourceMetadata::forConfiguration($this->configuration)->jsonSerialize();

        $this->assertSame(['mcp:read', 'mcp:write'], $document['scopes_supported']);
    }

    public function testCarriesAResourceNameWhenOneIsGiven(): void
    {
        $document = ProtectedResourceMetadata::forConfiguration($this->configuration, 'Example Blog')->jsonSerialize();

        $this->assertSame('Example Blog', $document['resource_name']);
    }

    // --- Where the document is served (RFC 9728 §3.1) ---

    /**
     * The configured resource is `https://example.com/mcp`, so the document belongs at the URL with
     * that path INSERTED. Serving only the bare well-known path 404s a conforming client at the
     * first hop of discovery — which is what this server did before `WellKnownPath` existed.
     */
    public function testServesTheDocumentAtThePathInsertedUrl(): void
    {
        $metadata = ProtectedResourceMetadata::forConfiguration($this->configuration);

        $this->assertSame('/.well-known/oauth-protected-resource/mcp', $metadata->getPrimaryMetadataPath());
    }

    public function testKeepsTheBareWellKnownPathAsAFallback(): void
    {
        $metadata = ProtectedResourceMetadata::forConfiguration($this->configuration);

        $this->assertSame(
            ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource'],
            $metadata->getMetadataPaths(),
        );
    }

    public function testAResourceWithNoPathIsServedAtTheBarePathAlone(): void
    {
        $configuration = $this->configurationFor('https://example.com', 'https://example.com');

        $this->assertSame(
            ['/.well-known/oauth-protected-resource'],
            ProtectedResourceMetadata::forConfiguration($configuration)->getMetadataPaths(),
        );
    }

    public function testAResourceWithANestedPathInsertsTheWholePath(): void
    {
        $configuration = $this->configurationFor('https://example.com', 'https://example.com/api/mcp');

        $this->assertSame(
            '/.well-known/oauth-protected-resource/api/mcp',
            ProtectedResourceMetadata::forConfiguration($configuration)->getPrimaryMetadataPath(),
        );
    }

    private function configurationFor(string $issuer, string $resource): Configuration
    {
        return new Configuration(
            issuer:           $issuer,
            resource:         $resource,
            storageDirectory: $this->configuration->storageDirectory,
            privateKeyPath:   $this->configuration->privateKeyPath,
            publicKeyPath:    $this->configuration->publicKeyPath,
            encryptionKey:    $this->configuration->encryptionKey,
            scopes:           $this->configuration->scopes,
        );
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Bridge;

use VoltCMS\MCP\Bridge\ProtectedResourceMetadata;
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

    public function testServesTheDocumentAtTheWellKnownPathTheSdkExpects(): void
    {
        $metadata = ProtectedResourceMetadata::forConfiguration($this->configuration);

        $this->assertSame('/.well-known/oauth-protected-resource', $metadata->getPrimaryMetadataPath());
    }
}

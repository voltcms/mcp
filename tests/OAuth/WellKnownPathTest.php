<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\WellKnownPath;

/**
 * RFC 8414 §3.1 and RFC 9728 §3.1: the well-known segment goes BETWEEN the host and the path, not
 * after it.
 *
 * The case that matters is `testInsertsThePathOfAnIdentifierThatHasOne`. Serving only the bare path
 * for a resource like `https://example.com/mcp` means a conforming client 404s at the first hop of
 * discovery, before this server has told it anything — which is exactly what happened before this
 * class existed.
 */
final class WellKnownPathTest extends TestCase
{
    private const WELL_KNOWN = '/.well-known/oauth-protected-resource';

    public function testAnIdentifierWithNoPathGetsTheBareWellKnownPath(): void
    {
        $this->assertSame(
            [self::WELL_KNOWN],
            WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com'),
        );
    }

    public function testATrailingSlashIsNotAPath(): void
    {
        $this->assertSame(
            [self::WELL_KNOWN],
            WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com/'),
        );
    }

    public function testInsertsThePathOfAnIdentifierThatHasOne(): void
    {
        $this->assertSame(
            [self::WELL_KNOWN . '/mcp', self::WELL_KNOWN],
            WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com/mcp'),
        );
    }

    public function testInsertsAMultiSegmentPathWhole(): void
    {
        $this->assertSame(
            [self::WELL_KNOWN . '/api/mcp', self::WELL_KNOWN],
            WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com/api/mcp'),
        );
    }

    /** The first entry is what the `WWW-Authenticate` challenge publishes, so it has to be the conforming one. */
    public function testTheInsertedPathLeads(): void
    {
        $paths = WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com/mcp');

        $this->assertSame(self::WELL_KNOWN . '/mcp', $paths[0]);
    }

    public function testTheBareWellKnownPathIsKeptAsAFallback(): void
    {
        $paths = WellKnownPath::forIdentifier(self::WELL_KNOWN, 'https://example.com/mcp');

        $this->assertContains(self::WELL_KNOWN, $paths);
    }

    public function testIgnoresAPortAndAScheme(): void
    {
        $this->assertSame(
            [self::WELL_KNOWN . '/mcp', self::WELL_KNOWN],
            WellKnownPath::forIdentifier(self::WELL_KNOWN, 'http://localhost:8080/mcp'),
        );
    }

    public function testWorksForTheAuthorizationServerSegmentToo(): void
    {
        $this->assertSame(
            ['/.well-known/oauth-authorization-server/blog', '/.well-known/oauth-authorization-server'],
            WellKnownPath::forIdentifier('/.well-known/oauth-authorization-server', 'https://example.com/blog'),
        );
    }

    public function testNeverReturnsAnEmptyList(): void
    {
        $this->assertNotSame([], WellKnownPath::forIdentifier(self::WELL_KNOWN, 'not-a-url'));
    }
}

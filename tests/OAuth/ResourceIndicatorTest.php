<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth;

use League\OAuth2\Server\Exception\OAuthServerException;
use VoltCMS\MCP\OAuth\ResourceIndicator;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * RFC 8707's `resource`, which league knows nothing about. The comparison has to be exact for the
 * same reason the store's identifier comparison does: anything looser hands an attacker a way to
 * name a resource that is not this one and be told yes.
 */
final class ResourceIndicatorTest extends RepositoryTestCase
{
    public function testAnAbsentResourceIsAllowed(): void
    {
        $this->expectNotToPerformAssertions();

        $this->indicator()->guard([]);
    }

    public function testTheConfiguredResourceIsAllowed(): void
    {
        $this->expectNotToPerformAssertions();

        $this->indicator()->guard(['resource' => 'https://example.com/mcp']);
    }

    public function testATrailingSlashIsNotADifferentResource(): void
    {
        $this->expectNotToPerformAssertions();

        $this->indicator()->guard(['resource' => 'https://example.com/mcp/']);
    }

    public function testTheSchemeAndHostAreComparedCaseInsensitively(): void
    {
        $this->expectNotToPerformAssertions();

        $this->indicator()->guard(['resource' => 'HTTPS://EXAMPLE.COM/mcp']);
    }

    public function testThePathIsComparedCaseSensitively(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => 'https://example.com/MCP']);
    }

    public function testAnotherServerIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => 'https://attacker.example/mcp']);
    }

    public function testASubpathOfThisResourceIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => 'https://example.com/mcp/tools']);
    }

    public function testAPrefixOfThisResourceIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => 'https://example.com']);
    }

    public function testAResourceThatIsNotAUrlIsRefused(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => 'mcp']);
    }

    public function testAResourceSentAsAnArrayIsCheckedEntryByEntry(): void
    {
        $this->expectException(OAuthServerException::class);

        $this->indicator()->guard(['resource' => ['https://example.com/mcp', 'https://attacker.example/mcp']]);
    }

    public function testTheErrorNamesTheRfc8707Code(): void
    {
        try {
            $this->indicator()->guard(['resource' => 'https://attacker.example/mcp']);
        } catch (OAuthServerException $exception) {
            $this->assertSame(ResourceIndicator::ERROR_INVALID_TARGET, $exception->getErrorType());

            return;
        }

        $this->fail('A foreign resource was accepted.');
    }

    private function indicator(): ResourceIndicator
    {
        return new ResourceIndicator($this->configuration);
    }
}

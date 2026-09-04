<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataFetcherInterface;

/**
 * Serves Client ID Metadata Documents from an array. PLAN.md §6: no network in tests, ever — and
 * counting the fetches is also how the cache is tested.
 */
final class StubClientIdMetadataFetcher implements ClientIdMetadataFetcherInterface
{
    public int $fetches = 0;

    /** @var array<string, string> */
    private array $documents;

    /**
     * @param array<string, string> $documents URL => body.
     */
    public function __construct(array $documents = [])
    {
        $this->documents = $documents;
    }

    /**
     * @param array<string, mixed> $document
     */
    public function serve(string $url, array $document): void
    {
        $this->documents[$url] = (string) json_encode($document);
    }

    public function serveRaw(string $url, string $body): void
    {
        $this->documents[$url] = $body;
    }

    public function fetch(string $url): string
    {
        $this->fetches++;

        if (!isset($this->documents[$url])) {
            throw new \RuntimeException('No document is served at ' . $url);
        }

        return $this->documents[$url];
    }
}

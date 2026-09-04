<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Clients;

use VoltCMS\MCP\OAuth\Clients\ClientIdMetadataResolver;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;
use VoltCMS\MCP\Tests\Support\StubClientIdMetadataFetcher;

/**
 * Resolving a `client_id` that is a URL, and remembering the answer.
 *
 * The cache is a security control before it is an optimisation. Without it, every authorization
 * request naming a URL makes this server fetch that URL — so a few requests a second aimed at
 * `?client_id=https://victim.example/…` turn a personal blog into an amplifier pointed at somebody
 * else. Caching refusals as well as successes is what bounds that whatever an attacker does.
 */
final class ClientIdMetadataResolverTest extends RepositoryTestCase
{
    private const URL = 'https://claude.ai/client.json';

    private StubClientIdMetadataFetcher $fetcher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new StubClientIdMetadataFetcher();
        $this->fetcher->serve(self::URL, [
            'client_id'     => self::URL,
            'client_name'   => 'Claude Desktop',
            'redirect_uris' => ['https://claude.ai/callback'],
        ]);
    }

    public function testResolvesAServedDocumentToAClient(): void
    {
        $client = $this->resolver()->resolve(self::URL);

        $this->assertSame(self::URL, $client?->getIdentifier());
        $this->assertSame('Claude Desktop', $client?->getName());
    }

    public function testTheResolvedClientIsPublic(): void
    {
        $this->assertFalse((bool) $this->resolver()->resolve(self::URL)?->isConfidential());
    }

    public function testRecognisesAMetadataUrl(): void
    {
        $this->assertTrue(ClientIdMetadataResolver::looksLikeMetadataUrl('https://claude.ai/client.json'));
    }

    public function testDoesNotMistakeARegisteredIdentifierForAMetadataUrl(): void
    {
        $this->assertFalse(ClientIdMetadataResolver::looksLikeMetadataUrl('claude-desktop'));
    }

    public function testDoesNotTreatPlainHttpAsAMetadataUrl(): void
    {
        $this->assertFalse(ClientIdMetadataResolver::looksLikeMetadataUrl('http://claude.ai/client.json'));
    }

    // --- Refusals ---

    public function testAnUnreachableDocumentResolvesToNoClient(): void
    {
        $this->assertNull($this->resolver()->resolve('https://nowhere.example/client.json'));
    }

    public function testADocumentThatIsNotJsonResolvesToNoClient(): void
    {
        $this->fetcher->serveRaw(self::URL, 'not json at all');

        $this->assertNull($this->resolver()->resolve(self::URL));
    }

    public function testADocumentThatIsAJsonScalarResolvesToNoClient(): void
    {
        $this->fetcher->serveRaw(self::URL, '"just a string"');

        $this->assertNull($this->resolver()->resolve(self::URL));
    }

    public function testADocumentClaimingAnotherClientIdResolvesToNoClient(): void
    {
        $this->fetcher->serve(self::URL, [
            'client_id'     => 'https://someone-else.example/client.json',
            'redirect_uris' => ['https://claude.ai/callback'],
        ]);

        $this->assertNull($this->resolver()->resolve(self::URL));
    }

    // --- The cache ---

    public function testFetchesOnceAndAnswersFromTheCacheAfterwards(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve(self::URL);
        $resolver->resolve(self::URL);

        $this->assertSame(1, $this->fetcher->fetches);
    }

    public function testTheCachedClientIsTheSameClient(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve(self::URL);

        $this->assertSame('Claude Desktop', $resolver->resolve(self::URL)?->getName());
    }

    /**
     * The refusal is cached too, or a URL that fails is one an attacker can make this server fetch
     * as often as it likes.
     */
    public function testARefusalIsCachedSoAFailingUrlIsNotFetchedAgain(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve('https://nowhere.example/client.json');
        $resolver->resolve('https://nowhere.example/client.json');

        $this->assertSame(1, $this->fetcher->fetches);
    }

    public function testACachedRefusalStillResolvesToNoClient(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve('https://nowhere.example/client.json');

        $this->assertNull($resolver->resolve('https://nowhere.example/client.json'));
    }

    public function testARefusalIsForgottenSoonerThanASuccess(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve('https://nowhere.example/client.json', new \DateTimeImmutable('2026-01-01 12:00:00'));

        $this->assertSame(1, $resolver->purgeExpired(new \DateTimeImmutable('2026-01-01 12:10:00')));
    }

    public function testASuccessOutlivesTheRefusalWindow(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve(self::URL, new \DateTimeImmutable('2026-01-01 12:00:00'));

        $this->assertSame(0, $resolver->purgeExpired(new \DateTimeImmutable('2026-01-01 12:10:00')));
    }

    public function testForgettingADocumentMakesTheNextResolveFetchAgain(): void
    {
        $resolver = $this->resolver();
        $resolver->resolve(self::URL);
        $resolver->forget(self::URL);
        $resolver->resolve(self::URL);

        $this->assertSame(2, $this->fetcher->fetches);
    }

    /**
     * A document that changed is picked up when its cache entry expires, rather than being pinned
     * for the life of the store.
     */
    public function testAnExpiredCacheEntryIsRefetched(): void
    {
        $resolver = new ClientIdMetadataResolver($this->configuration, $this->fetcher, null, 1);
        $resolver->resolve(self::URL, new \DateTimeImmutable('-1 hour'));
        $resolver->resolve(self::URL);

        $this->assertSame(2, $this->fetcher->fetches);
    }

    private function resolver(): ClientIdMetadataResolver
    {
        return new ClientIdMetadataResolver($this->configuration, $this->fetcher);
    }
}

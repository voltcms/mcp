<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Repositories\FileDbRepository;
use VoltCMS\UserAccess\AuditLog;

/**
 * Turns a `client_id` that is a URL into a client, and remembers the answer.
 *
 * The cache is not an optimisation, or not only one. Without it every authorization request from a
 * CIMD client makes this server fetch a URL that request chose — so a handful of requests a second
 * to `?client_id=https://victim.example/large-thing` turns a personal blog into a small amplifier
 * pointed at somebody else. Caching the answer, and caching the REFUSAL too, bounds that to one
 * fetch per URL per TTL whatever an attacker does.
 *
 * Refusals are cached for a shorter time than successes: a document that was malformed an hour ago
 * is probably still malformed, but a client fixing its document should not be locked out for a day.
 *
 * Everything reachable from here is injected, which is what lets the whole class be exercised
 * without a network — PLAN.md §6.
 */
final class ClientIdMetadataResolver extends FileDbRepository
{
    public const FIELD_DOCUMENT = 'document';
    public const FIELD_REFUSED  = 'refused';

    /** Long enough to be a cache, short enough that a client that changes its redirect URIs is not stuck for a day. */
    public const DEFAULT_TTL_SECONDS = 3600;

    public const REFUSAL_TTL_SECONDS = 300;

    private readonly ClientIdMetadataFetcherInterface $fetcher;
    private readonly int $ttlSeconds;

    public function __construct(
        Configuration $configuration,
        ?ClientIdMetadataFetcherInterface $fetcher = null,
        ?AuditLog $auditLog = null,
        int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
    ) {
        parent::__construct($configuration, $auditLog);

        $this->fetcher    = $fetcher ?? new StreamClientIdMetadataFetcher();
        $this->ttlSeconds = max(1, $ttlSeconds);
    }

    protected function collection(): string
    {
        return 'client_id_metadata';
    }

    /** Whether this identifier is a CIMD client id at all, rather than a registered one. */
    public static function looksLikeMetadataUrl(string $clientId): bool
    {
        return str_starts_with(strtolower($clientId), 'https://');
    }

    /**
     * The client this URL describes, or null if it does not describe one this server will accept.
     *
     * Null for every kind of failure — unreachable, not JSON, claiming a different `client_id`,
     * naming an unusable redirect URI — because the caller is `ClientRepository::getClientEntity()`
     * and its answer for all of them is the same: there is no such client.
     */
    public function resolve(string $url, ?\DateTimeImmutable $now = null): ?Client
    {
        $cached = $this->cached($url);

        if ($cached !== null) {
            return $cached === [] ? null : $this->toClient($cached, $url);
        }

        try {
            $document = $this->document($this->fetcher->fetch($url));
        } catch (\Throwable) {
            $this->remember($url, null, $now);
            $this->audit('client_metadata.refused', ['client_id' => $url]);

            return null;
        }

        try {
            $metadata = ClientIdMetadataDocument::fromDocument($document, $url);
        } catch (\InvalidArgumentException $exception) {
            $this->remember($url, null, $now);
            $this->audit('client_metadata.refused', ['client_id' => $url, 'reason' => $exception->getCode()]);

            return null;
        }

        $this->remember($url, [
            'client_name'   => $metadata->clientName,
            'redirect_uris' => $metadata->redirectUris,
            'grant_types'   => $metadata->grantTypes,
        ], $now);

        $this->audit('client_metadata.accepted', ['client_id' => $url]);

        return $metadata->toClient();
    }

    /** Drop a cached document, so the next authorization re-fetches it. */
    public function forget(string $url): void
    {
        $this->revoke($url);
    }

    // --- Cache ---

    /**
     * @return array<string, mixed>|null Null when nothing usable is cached; `[]` for a cached refusal.
     */
    private function cached(string $url): ?array
    {
        $record = $this->find($url);

        if ($record === null) {
            return null;
        }

        $expiresAt = $record[self::FIELD_EXPIRES_AT] ?? null;

        if (!is_int($expiresAt) || $expiresAt <= time() || ($record[self::FIELD_REVOKED] ?? false) === true) {
            return null;
        }

        if (($record[self::FIELD_REFUSED] ?? false) === true) {
            return [];
        }

        $document = $record[self::FIELD_DOCUMENT] ?? null;

        return is_array($document) ? $document : null;
    }

    /**
     * @param array<string, mixed>|null $document Null records a refusal.
     */
    private function remember(string $url, ?array $document, ?\DateTimeImmutable $now): void
    {
        $seconds = $document === null ? self::REFUSAL_TTL_SECONDS : $this->ttlSeconds;

        $this->upsert([
            self::FIELD_OAUTH_ID   => $url,
            self::FIELD_DOCUMENT   => $document ?? [],
            self::FIELD_REFUSED    => $document === null,
            self::FIELD_EXPIRES_AT => ($now ?? new \DateTimeImmutable())->getTimestamp() + $seconds,
            self::FIELD_REVOKED    => false,
        ]);
    }

    /**
     * @param array<string, mixed> $document
     */
    private function toClient(array $document, string $url): Client
    {
        /** @var list<string> $redirectUris */
        $redirectUris = is_array($document['redirect_uris'] ?? null) ? array_values($document['redirect_uris']) : [];

        /** @var list<string> $grantTypes */
        $grantTypes = is_array($document['grant_types'] ?? null) ? array_values($document['grant_types']) : [];

        return new Client(
            $url,
            is_string($document['client_name'] ?? null) ? $document['client_name'] : $url,
            $redirectUris,
            false,
            $grantTypes,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function document(string $body): array
    {
        $decoded = json_decode($body, true, 16, JSON_THROW_ON_ERROR);

        if (!is_array($decoded)) {
            throw new \InvalidArgumentException('A client metadata document must be a JSON object.');
        }

        return $decoded;
    }
}

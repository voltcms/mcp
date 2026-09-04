<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use VoltCMS\FileDB\FileDB;
use VoltCMS\MCP\Configuration;
use VoltCMS\UserAccess\AuditLog;
use VoltCMS\UserAccess\Lock;

/**
 * The find / put / revoke shared by every FileDB-backed OAuth repository.
 *
 * Two properties of the store shape everything below.
 *
 * 1. `FileDB::create()` always generates its own UUID, so an OAuth identifier can never be the
 *    document id. Records carry it in an `oauth_id` field instead, and every lookup is a scan.
 *    That is O(n) per token validation — irrelevant at the scale this package targets, a
 *    documented ceiling as a library. See PLAN.md §4.5.
 *
 * 2. `FileDB::read(null, [...])`'s search MUST NOT be used to resolve an identifier, and this
 *    class never calls it. Its matcher is `strcasecmp()` with `*` treated as a wildcard, so a
 *    lookup for the attacker-supplied `client_id` of `claude*` matches a stored `claude-desktop`,
 *    and `CLAUDE-DESKTOP` matches it too. Client ids and token ids arrive straight from the
 *    request, so delegating the comparison would hand an attacker prefix matching over the
 *    credential store and drop roughly a bit of entropy per alphabetic character of every token
 *    identifier. `find()` scans and compares exactly, in constant time. See PLAN.md §4.8.
 *
 * Reads are unlocked — the worst case is observing pre-write state — while every mutation runs
 * inside `Lock::exclusive()`, which is reentrant and so composes with useraccess's own writes.
 */
abstract class FileDbRepository
{
    public const FIELD_OAUTH_ID   = 'oauth_id';
    public const FIELD_REVOKED    = 'revoked';
    public const FIELD_EXPIRES_AT = 'expires_at';

    private readonly FileDB $db;

    public function __construct(
        protected readonly Configuration $configuration,
        protected readonly ?AuditLog $auditLog = null,
    ) {
        $this->db = new FileDB($configuration->storageDirectory . DIRECTORY_SEPARATOR . $this->collection());
    }

    /** Directory name of this repository's collection, below the configured storage directory. */
    abstract protected function collection(): string;

    // --- Reads ---

    /**
     * Exact, case-sensitive lookup by OAuth identifier.
     *
     * @return array<string, mixed>|null
     */
    protected function find(string $oauthId): ?array
    {
        if ($oauthId === '') {
            return null;
        }

        foreach ($this->db->readAll() as $record) {
            $candidate = $record[self::FIELD_OAUTH_ID] ?? null;

            if (is_string($candidate) && hash_equals($candidate, $oauthId)) {
                return $record;
            }
        }

        return null;
    }

    /**
     * A record that is absent, flagged, or past its expiry reads as revoked.
     *
     * Absent is the important one: if the store is unreadable, has been emptied, or the
     * identifier was never issued here, the only safe answer is "revoked". Answering "valid" for
     * a token this server cannot find would accept anything that parses.
     */
    protected function isRevoked(string $oauthId): bool
    {
        $record = $this->find($oauthId);

        if ($record === null) {
            return true;
        }

        if (($record[self::FIELD_REVOKED] ?? false) === true) {
            return true;
        }

        $expiresAt = $record[self::FIELD_EXPIRES_AT] ?? null;

        return is_int($expiresAt) && $expiresAt <= time();
    }

    // --- Mutations ---

    /**
     * @param array<string, mixed> $record
     *
     * @throws UniqueTokenIdentifierConstraintViolationException if the identifier is already used.
     */
    protected function insert(array $record): void
    {
        Lock::exclusive(function () use ($record): void {
            $oauthId = $record[self::FIELD_OAUTH_ID] ?? '';

            if (!is_string($oauthId) || $oauthId === '' || $this->find($oauthId) !== null) {
                throw UniqueTokenIdentifierConstraintViolationException::create();
            }

            $this->db->create($record);
        });
    }

    /**
     * Flag a record revoked. A record that is not there is already revoked by definition, so
     * this is a no-op rather than a failure — league revokes optimistically.
     */
    protected function revoke(string $oauthId): void
    {
        Lock::exclusive(function () use ($oauthId): void {
            $record = $this->find($oauthId);

            if ($record === null) {
                return;
            }

            $this->db->update((string) $record[FileDB::ATTRIBUTE_ID], [self::FIELD_REVOKED => true]);
        });
    }

    /**
     * Delete every record that expired before $now. Nothing calls this on a schedule: a
     * flat-file deployment has no daemon, so sweeping is the consuming application's decision
     * (a cron entry, or a probability on write). Left uncalled, the collection grows without
     * bound and every lookup slows with it.
     *
     * @return int Number of records deleted.
     */
    public function purgeExpired(?\DateTimeImmutable $now = null): int
    {
        $cutoff = ($now ?? new \DateTimeImmutable())->getTimestamp();

        return (int) Lock::exclusive(function () use ($cutoff): int {
            $deleted = 0;

            foreach ($this->db->readAll() as $record) {
                $expiresAt = $record[self::FIELD_EXPIRES_AT] ?? null;

                if (is_int($expiresAt) && $expiresAt <= $cutoff) {
                    $this->db->delete((string) $record[FileDB::ATTRIBUTE_ID]);
                    $deleted++;
                }
            }

            return $deleted;
        });
    }

    // --- Audit ---

    /**
     * @param array<string, scalar|null> $context
     */
    protected function audit(string $event, array $context = []): void
    {
        $this->auditLog?->record(array_merge(['event' => $event], $context));
    }
}

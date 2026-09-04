<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use VoltCMS\MCP\OAuth\Repositories\FileDbRepository;
use VoltCMS\MCP\Tests\Support\FixtureRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * The store behaviour every repository inherits.
 *
 * The identifier-matching tests here are the third upgrade tripwire. FileDB's own search matches
 * with `strcasecmp()` and treats `*` as a wildcard, and the identifiers passed to these lookups
 * come straight out of an HTTP request. If these tests ever start failing, something has begun
 * delegating comparison to FileDB again, and prefix matching over the credential store came back
 * with it. Treat that as a security regression, not a test to update. See PLAN.md §4.8.
 */
final class FileDbRepositoryTest extends RepositoryTestCase
{
    private FixtureRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new FixtureRepository($this->configuration);
    }

    // --- Identifier matching ---

    public function testFindsARecordByItsExactIdentifier(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'claude-desktop']);

        $record = $this->repository->findRecord('claude-desktop');

        $this->assertSame('claude-desktop', $record[FileDbRepository::FIELD_OAUTH_ID] ?? null);
    }

    public function testDoesNotMatchAnIdentifierByAPrefixWildcard(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'claude-desktop']);

        $this->assertNull($this->repository->findRecord('claude*'));
    }

    public function testDoesNotMatchAnIdentifierByASuffixWildcard(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'claude-desktop']);

        $this->assertNull($this->repository->findRecord('*desktop'));
    }

    public function testMatchesIdentifiersCaseSensitively(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'claude-desktop']);

        $this->assertNull($this->repository->findRecord('CLAUDE-DESKTOP'));
    }

    public function testFindsNothingForAnEmptyIdentifier(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'claude-desktop']);

        $this->assertNull($this->repository->findRecord(''));
    }

    // --- Revocation ---

    public function testTreatsAnUnknownRecordAsRevoked(): void
    {
        $this->assertTrue($this->repository->recordIsRevoked('never-issued'));
    }

    public function testTreatsALiveRecordAsNotRevoked(): void
    {
        $this->repository->insertRecord([
            FileDbRepository::FIELD_OAUTH_ID   => 'live',
            FileDbRepository::FIELD_EXPIRES_AT => time() + 3600,
            FileDbRepository::FIELD_REVOKED    => false,
        ]);

        $this->assertFalse($this->repository->recordIsRevoked('live'));
    }

    public function testTreatsARevokedRecordAsRevoked(): void
    {
        $this->repository->insertRecord([
            FileDbRepository::FIELD_OAUTH_ID   => 'live',
            FileDbRepository::FIELD_EXPIRES_AT => time() + 3600,
            FileDbRepository::FIELD_REVOKED    => false,
        ]);

        $this->repository->revokeRecord('live');

        $this->assertTrue($this->repository->recordIsRevoked('live'));
    }

    public function testTreatsAnExpiredRecordAsRevoked(): void
    {
        $this->repository->insertRecord([
            FileDbRepository::FIELD_OAUTH_ID   => 'stale',
            FileDbRepository::FIELD_EXPIRES_AT => time() - 1,
            FileDbRepository::FIELD_REVOKED    => false,
        ]);

        $this->assertTrue($this->repository->recordIsRevoked('stale'));
    }

    public function testRevokingAnUnknownRecordIsANoOp(): void
    {
        $this->repository->revokeRecord('never-issued');

        $this->assertNull($this->repository->findRecord('never-issued'));
    }

    public function testRevokingOneRecordLeavesTheOthersAlone(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'first', FileDbRepository::FIELD_REVOKED => false]);
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'second', FileDbRepository::FIELD_REVOKED => false]);

        $this->repository->revokeRecord('first');

        $this->assertFalse($this->repository->recordIsRevoked('second'));
    }

    // --- Uniqueness ---

    public function testRefusesToInsertADuplicateIdentifier(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'once']);

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'once']);
    }

    public function testRefusesToInsertARecordWithoutAnIdentifier(): void
    {
        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);

        $this->repository->insertRecord(['unrelated' => 'value']);
    }

    // --- Purging ---

    public function testPurgesExpiredRecords(): void
    {
        $this->repository->insertRecord([
            FileDbRepository::FIELD_OAUTH_ID   => 'stale',
            FileDbRepository::FIELD_EXPIRES_AT => time() - 60,
        ]);

        $this->assertSame(1, $this->repository->purgeExpired());
        $this->assertNull($this->repository->findRecord('stale'));
    }

    public function testKeepsUnexpiredRecordsWhenPurging(): void
    {
        $this->repository->insertRecord([
            FileDbRepository::FIELD_OAUTH_ID   => 'fresh',
            FileDbRepository::FIELD_EXPIRES_AT => time() + 3600,
        ]);

        $this->assertSame(0, $this->repository->purgeExpired());
        $this->assertNotNull($this->repository->findRecord('fresh'));
    }

    // --- Layout ---

    public function testWritesItsRecordsBelowTheConfiguredStorageDirectory(): void
    {
        $this->repository->insertRecord([FileDbRepository::FIELD_OAUTH_ID => 'anything']);

        $this->assertDirectoryExists($this->storageDirectory . '/fixtures');
    }
}

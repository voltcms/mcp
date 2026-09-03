<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\OAuth\Repositories\FileDbRepository;

/**
 * Exposes FileDbRepository's protected surface so the shared find / insert / revoke behaviour can
 * be tested once, directly, instead of five times through its subclasses.
 */
final class FixtureRepository extends FileDbRepository
{
    protected function collection(): string
    {
        return 'fixtures';
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findRecord(string $oauthId): ?array
    {
        return $this->find($oauthId);
    }

    /**
     * @param array<string, mixed> $record
     */
    public function insertRecord(array $record): void
    {
        $this->insert($record);
    }

    public function revokeRecord(string $oauthId): void
    {
        $this->revoke($oauthId);
    }

    public function recordIsRevoked(string $oauthId): bool
    {
        return $this->isRevoked($oauthId);
    }
}

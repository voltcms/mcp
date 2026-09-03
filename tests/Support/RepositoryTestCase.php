<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Configuration;

/**
 * Base for every test that needs a store on disk: one temp directory per test, removed
 * afterwards, and a Configuration pointed at it.
 */
abstract class RepositoryTestCase extends TestCase
{
    protected string $storageDirectory;
    protected Configuration $configuration;

    protected function setUp(): void
    {
        parent::setUp();

        $this->storageDirectory = TempDirectory::create();
        $this->configuration    = new Configuration(
            issuer:           'https://example.com',
            resource:         'https://example.com/mcp',
            storageDirectory: $this->storageDirectory,
            privateKeyPath:   $this->storageDirectory . '/keys/private.key',
            publicKeyPath:    $this->storageDirectory . '/keys/public.key',
            encryptionKey:    'PsUqBQ0YBaNlfyE8dLUt9dK4rMPVLQhZ8OrZfEXvOBs=',
            scopes:           ['mcp:read', 'mcp:write'],
        );
    }

    protected function tearDown(): void
    {
        TempDirectory::remove($this->storageDirectory);

        parent::tearDown();
    }
}

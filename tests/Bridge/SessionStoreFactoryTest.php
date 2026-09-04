<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Bridge;

use Symfony\Component\Uid\Uuid;
use VoltCMS\MCP\Bridge\SessionStoreFactory;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * Handshake-era sessions on disk.
 *
 * The two things worth asserting are the two the SDK leaves to the integrator: that the directory
 * is under the configured storage root rather than in a world-readable temp directory — a session
 * file is a live credential — and that something can sweep it, because nothing here runs on a
 * schedule.
 */
final class SessionStoreFactoryTest extends RepositoryTestCase
{
    public function testKeepsSessionsUnderTheConfiguredStorageDirectory(): void
    {
        $factory = new SessionStoreFactory($this->configuration);

        $this->assertStringStartsWith($this->configuration->storageDirectory, $factory->directory());
    }

    public function testTheSessionDirectoryIsGivenADenyAllHtaccess(): void
    {
        $factory = new SessionStoreFactory($this->configuration);
        $factory->create();

        $this->assertFileExists($factory->directory() . '/.htaccess');
    }

    public function testAStoredSessionCanBeReadBack(): void
    {
        $store = (new SessionStoreFactory($this->configuration))->create();
        $id    = Uuid::v4();

        $store->write($id, 'payload');

        $this->assertSame('payload', $store->read($id));
    }

    public function testPurgingRemovesASessionPastItsTtl(): void
    {
        $factory = new SessionStoreFactory($this->configuration, 60);
        $factory->create()->write(Uuid::v4(), 'payload');

        $this->assertSame(1, $factory->purge(new \DateTimeImmutable('+2 hours')));
    }

    public function testPurgingLeavesALiveSessionAlone(): void
    {
        $factory = new SessionStoreFactory($this->configuration, 3600);
        $factory->create()->write(Uuid::v4(), 'payload');

        $this->assertSame(0, $factory->purge());
    }

    public function testPurgingLeavesTheDenyAllFilesAlone(): void
    {
        $factory = new SessionStoreFactory($this->configuration, 60);
        $factory->create();

        $factory->purge(new \DateTimeImmutable('+2 hours'));

        $this->assertFileExists($factory->directory() . '/.htaccess');
    }
}

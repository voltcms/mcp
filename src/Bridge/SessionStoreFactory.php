<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Bridge;

use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Session\SessionStoreInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\UserAccess\Utils;

/**
 * The session store `mcp/sdk` needs for handshake-era clients.
 *
 * The 2025 MCP lifecycle is stateful: a client calls `initialize`, is given an `Mcp-Session-Id`,
 * and every later request belongs to that session. The SDK's `StreamableHttpTransport` serves both
 * eras from one endpoint, so a server that wants to talk to anything older than 2026-07-28 needs
 * somewhere to keep those sessions — and for a package whose whole premise is "no database", that
 * is the SDK's own `FileSessionStore`.
 *
 * Two things this adds over calling it directly, and they are the two that bite in deployment.
 *
 * **Where the directory lives.** It defaults under the configured storage directory, which is
 * already required to be outside the web root, rather than under `sys_get_temp_dir()` where a
 * shared host's other tenants can read it. A session file is a live credential for the duration of
 * its TTL.
 *
 * **Who sweeps it.** Nobody, unless someone does: there is no daemon. `mcp/sdk` garbage-collects
 * probabilistically as requests arrive, which is enough for a server that is used and not enough
 * for one that is not. `purge()` is here for the same cron entry that sweeps the token store.
 */
final class SessionStoreFactory
{
    public const DIRECTORY = 'mcp_sessions';

    /** Matches the SDK's own default; a handshake-era session outliving an access token is pointless. */
    public const DEFAULT_TTL_SECONDS = 3600;

    public function __construct(
        private readonly Configuration $configuration,
        private readonly int $ttlSeconds = self::DEFAULT_TTL_SECONDS,
    ) {
    }

    public function create(): SessionStoreInterface
    {
        $directory = $this->directory();

        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        Utils::protectDirectory($directory);

        return new FileSessionStore($directory, $this->ttlSeconds);
    }

    /**
     * Delete session files past their TTL.
     *
     * @return int Number of files deleted.
     */
    public function purge(?\DateTimeImmutable $now = null): int
    {
        $cutoff  = ($now ?? new \DateTimeImmutable())->getTimestamp() - $this->ttlSeconds;
        $files   = glob($this->directory() . DIRECTORY_SEPARATOR . '*');
        $deleted = 0;

        foreach ($files === false ? [] : $files as $file) {
            if (!is_file($file) || str_starts_with(basename($file), '.') || basename($file) === 'index.html') {
                continue;
            }

            if ((int) @filemtime($file) < $cutoff) {
                @unlink($file);
                $deleted++;
            }
        }

        return $deleted;
    }

    public function directory(): string
    {
        return $this->configuration->storageDirectory . DIRECTORY_SEPARATOR . self::DIRECTORY;
    }
}

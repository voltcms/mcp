<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

/**
 * The one place tests are allowed to touch the filesystem.
 *
 * Every store in this package is a directory, so nearly every test needs one; going through a
 * single helper keeps them out of the repository tree, gives each test its own root, and makes
 * cleanup something a test cannot forget to do differently from its neighbours.
 */
final class TempDirectory
{
    public static function create(): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'voltcms-mcp-' . bin2hex(random_bytes(8));

        if (!mkdir($path, 0700, true) && !is_dir($path)) {
            throw new \RuntimeException('Unable to create temporary directory: ' . $path);
        }

        return $path;
    }

    public static function remove(string $path): void
    {
        if (!is_dir($path)) {
            return;
        }

        $entries = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST,
        );

        foreach ($entries as $entry) {
            /** @var \SplFileInfo $entry */
            $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
        }

        rmdir($path);
    }
}

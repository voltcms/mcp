<?php

declare(strict_types=1);

namespace Example\Blog;

/**
 * The application's actual content, and the only part of this example that is about a blog.
 *
 * Every method here becomes an MCP tool. Note what they take and return: plain scalars and arrays,
 * with real type declarations and docblocks, because that is what `mcp/sdk` reads to build a tool's
 * input schema. A parameter typed `mixed` is a tool the model cannot call correctly.
 */
final class Posts
{
    public function __construct(private readonly string $directory)
    {
    }

    /**
     * List the posts on this site, newest first.
     *
     * @param int $limit How many to return, at most.
     *
     * @return list<array{slug: string, title: string, modified: string}>
     */
    public function list(int $limit = 20): array
    {
        $posts = [];

        foreach ($this->files() as $file) {
            $posts[] = [
                'slug'     => basename($file, '.md'),
                'title'    => $this->title($file),
                'modified' => date('c', (int) filemtime($file)),
            ];
        }

        usort($posts, static fn (array $a, array $b): int => strcmp($b['modified'], $a['modified']));

        return array_slice($posts, 0, max(1, $limit));
    }

    /**
     * Read one post.
     *
     * @param string $slug The post's slug, as returned by the listing.
     */
    public function read(string $slug): string
    {
        $path = $this->pathFor($slug);

        if ($path === null) {
            throw new \InvalidArgumentException('There is no post with that slug.');
        }

        return (string) file_get_contents($path);
    }

    /**
     * Replace the body of one post. Requires the `mcp:write` scope.
     *
     * @param string $slug     The post's slug.
     * @param string $markdown The new body, in Markdown.
     */
    public function write(string $slug, string $markdown): string
    {
        $path = $this->pathFor($slug);

        if ($path === null) {
            throw new \InvalidArgumentException('There is no post with that slug.');
        }

        file_put_contents($path, $markdown);

        return 'Saved ' . $slug . '.';
    }

    /**
     * The slug is attacker-influenced — it arrives from a model, over the network — so it is
     * matched against the listing rather than concatenated into a path. `../../config` is a slug a
     * tool will be asked for eventually.
     */
    private function pathFor(string $slug): ?string
    {
        foreach ($this->files() as $file) {
            if (hash_equals(basename($file, '.md'), $slug)) {
                return $file;
            }
        }

        return null;
    }

    /**
     * @return list<string>
     */
    private function files(): array
    {
        return array_values(glob(rtrim($this->directory, '/') . '/*.md') ?: []);
    }

    private function title(string $file): string
    {
        $first = (string) strtok((string) file_get_contents($file), "\n");

        return trim(ltrim($first, '# ')) ?: basename($file, '.md');
    }
}

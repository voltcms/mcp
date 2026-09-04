<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth;

/**
 * Where a metadata document has to be served, given the identifier it describes.
 *
 * RFC 8414 §3.1 and RFC 9728 §3.1 define the same construction in the same words: the well-known
 * segment is inserted **between the host and the path** of the identifier, not appended to it.
 *
 * | Identifier | Document URL |
 * |---|---|
 * | `https://example.com` | `https://example.com/.well-known/oauth-protected-resource` |
 * | `https://example.com/mcp` | `https://example.com/.well-known/oauth-protected-resource/mcp` |
 * | `https://example.com/api/mcp` | `https://example.com/.well-known/oauth-protected-resource/api/mcp` |
 *
 * Getting this wrong is not a cosmetic error. A conforming client builds the inserted URL, and a
 * server that only answers the bare one returns 404 at the first hop of discovery — before it has
 * said anything about itself at all. The client cannot proceed and has nothing to report beyond
 * "could not connect".
 *
 * ## Why the bare path is kept as a fallback
 *
 * When the identifier has a path, this returns the inserted URL first and the bare one after it.
 * The bare one is there for clients that do not insert, and it is safe to serve because both RFCs
 * make the client check: RFC 8414 §3.3 requires the document's `issuer` to be identical to the one
 * it was looking for, and RFC 9728 §3.3 requires the same of `resource`. A client that arrives at
 * the bare URL looking for a *different* identifier therefore rejects what it finds, rather than
 * being misled by it.
 *
 * Order matters beyond preference: the first entry is what `mcp/sdk` publishes in its
 * `WWW-Authenticate` challenge, so the conforming URL has to lead.
 */
final class WellKnownPath
{
    /**
     * @param string $wellKnown  The well-known segment, with its leading slash.
     * @param string $identifier The issuer or resource URL the document describes.
     *
     * @return list<string> Most conformant first; never empty.
     */
    public static function forIdentifier(string $wellKnown, string $identifier): array
    {
        $path = trim((string) parse_url(trim($identifier), PHP_URL_PATH), '/');

        if ($path === '') {
            return [$wellKnown];
        }

        return [$wellKnown . '/' . $path, $wellKnown];
    }
}

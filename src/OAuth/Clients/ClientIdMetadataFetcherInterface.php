<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

/**
 * Fetches the bytes of a Client ID Metadata Document.
 *
 * It is an interface for one reason above all others: PLAN.md §6 says **no network in tests,
 * ever**, and a resolver that reached for `file_get_contents()` directly would make every test of
 * the surrounding validation either impossible or dependent on somebody else's uptime. The stub in
 * the suite returns bytes; everything interesting is then tested against real code.
 *
 * An implementation is responsible for the transport guards — HTTPS only, no redirects to another
 * host, no private or link-local address, a size cap, a short timeout. `SsrfGuard` exists to make
 * that a few lines rather than a research project.
 */
interface ClientIdMetadataFetcherInterface
{
    /**
     * @return string The document body.
     *
     * @throws \RuntimeException if it cannot be fetched, for any reason.
     */
    public function fetch(string $url): string;
}

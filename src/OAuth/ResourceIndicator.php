<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth;

use League\OAuth2\Server\Exception\OAuthServerException;
use VoltCMS\MCP\Configuration;

/**
 * The RFC 8707 `resource` parameter, checked against the one resource this server protects.
 *
 * league/oauth2-server does not know the parameter exists, so an unguarded endpoint would accept
 * `resource=https://elsewhere.example/mcp` and hand back a token whose `aud` is nonetheless this
 * server — an audience the client did not ask for and may not check. Refusing outright is the only
 * honest answer: this package serves a single MCP endpoint, and a request for a different one is a
 * request this server cannot satisfy.
 *
 * The counterpart tightening is `ResourceBoundAccessToken`, which puts the resource in `aud` in
 * the first place. Together they are PLAN.md §4.2: a token minted here is usable here and nowhere
 * else.
 */
final class ResourceIndicator
{
    public const PARAMETER = 'resource';

    /** RFC 8707 §2: the error code for a resource the server does not serve. */
    public const ERROR_INVALID_TARGET = 'invalid_target';

    /** league's own codes run 1..14; this one is ours. */
    public const EXCEPTION_INVALID_TARGET = 15;

    public function __construct(private readonly Configuration $configuration)
    {
    }

    /**
     * @param array<string, mixed> $parameters Query parameters, or a parsed form body.
     *
     * @throws OAuthServerException if a resource was named and it is not this one.
     */
    public function guard(array $parameters): void
    {
        $requested = $parameters[self::PARAMETER] ?? null;

        if ($requested === null) {
            // Absent is allowed: a single-resource server has exactly one answer, and clients
            // predating RFC 8707 never send it. The token is bound to that resource regardless.
            return;
        }

        foreach (is_array($requested) ? $requested : [$requested] as $candidate) {
            if (!is_string($candidate) || !$this->matches($candidate)) {
                throw new OAuthServerException(
                    'The requested resource is not served by this authorization server.',
                    self::EXCEPTION_INVALID_TARGET,
                    self::ERROR_INVALID_TARGET,
                    400,
                    'This server issues tokens for a single MCP endpoint only.',
                );
            }
        }
    }

    /**
     * Canonical comparison: scheme and host are case-insensitive per RFC 3986, one trailing slash
     * is not a different resource, and everything else must match byte for byte. A looser
     * comparison — a prefix match, a host-only match — would be the §4.8 wildcard hazard again,
     * one layer up.
     */
    private function matches(string $candidate): bool
    {
        return $this->canonical($candidate) === $this->canonical($this->configuration->resource);
    }

    private function canonical(string $url): string
    {
        $parts = parse_url(trim($url));

        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return "\0" . $url;
        }

        $canonical = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);

        if (isset($parts['port'])) {
            $canonical .= ':' . $parts['port'];
        }

        $canonical .= rtrim($parts['path'] ?? '', '/');

        if (isset($parts['query'])) {
            $canonical .= '?' . $parts['query'];
        }

        return $canonical;
    }
}

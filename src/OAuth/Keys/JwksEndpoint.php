<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Keys;

use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Endpoints\Endpoint;

/**
 * Publishes the JWKS that `mcp/sdk`'s `JwksProvider` — and any other RFC 7517 consumer — reads to
 * verify a token this server signed.
 *
 * Nothing secret is served here. A JWKS is public material by construction: the modulus and
 * exponent of a public key are already recoverable from any signature the private key produced.
 * What matters is that it stays CURRENT — a client that caches a key set through a rotation and
 * never refreshes will reject perfectly good tokens — so the cache window is deliberately short
 * relative to the retirement grace in `KeyManager`, leaving room for a stale cache to expire while
 * the retired key is still published.
 */
final class JwksEndpoint extends Endpoint
{
    public const CACHE_SECONDS = 600;

    private const THROTTLE_BUCKET = 'mcp.jwks';

    public function __construct(
        Configuration $configuration,
        private readonly KeyManager $keys,
        PsrAdapter $psr,
    ) {
        parent::__construct($configuration, $psr);
    }

    public function handle(Request $request): Response
    {
        if (!$request->isGet()) {
            return $this->methodNotAllowed('GET');
        }

        try {
            $jwks = $this->keys->jwks();
        } catch (\Throwable) {
            return $this->serverError();
        }

        return Response::json($jwks, Response::STATUS_OK, [
            'Cache-Control' => 'public, max-age=' . self::CACHE_SECONDS,
            'Pragma'        => 'cache',
        ]);
    }

    protected function throttleBucket(): string
    {
        return self::THROTTLE_BUCKET;
    }
}

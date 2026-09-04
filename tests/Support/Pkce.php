<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

/**
 * The S256 challenge, computed the way RFC 7636 §4.2 says and the way a real client would.
 *
 * Deliberately not a call into the package: a test that derived the challenge from the same code
 * the server verifies it with would pass even if both were wrong together.
 */
final class Pkce
{
    public static function verifier(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function challengeFor(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}

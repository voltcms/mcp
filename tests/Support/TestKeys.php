<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

/**
 * An RSA keypair for signing test tokens.
 *
 * Generated in memory rather than committed, so no private key ever sits in the repository, and
 * memoised because 2048-bit generation is slow enough to notice across a suite. P4's KeyManager
 * takes over generation for real deployments; this exists only so the token entity can be
 * exercised before it lands.
 */
final class TestKeys
{
    private static ?string $privateKey = null;

    public static function privateKeyPem(): string
    {
        if (self::$privateKey !== null) {
            return self::$privateKey;
        }

        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new \RuntimeException('Unable to generate an RSA keypair for the test suite.');
        }

        return self::$privateKey = $pem;
    }
}

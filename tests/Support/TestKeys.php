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
    private static ?string $privateKey        = null;
    private static ?string $publicKey         = null;
    private static ?string $foreignPrivateKey = null;
    private static ?string $foreignPublicKey  = null;

    public static function privateKeyPem(): string
    {
        self::generate();

        return (string) self::$privateKey;
    }

    public static function publicKeyPem(): string
    {
        self::generate();

        return (string) self::$publicKey;
    }

    /** A second keypair, for proving that a token signed by one key is refused by another. */
    public static function foreignPrivateKeyPem(): string
    {
        self::generateForeign();

        return (string) self::$foreignPrivateKey;
    }

    public static function foreignPublicKeyPem(): string
    {
        self::generateForeign();

        return (string) self::$foreignPublicKey;
    }

    private static function generate(): void
    {
        if (self::$privateKey !== null) {
            return;
        }

        [self::$privateKey, self::$publicKey] = self::keypair();
    }

    private static function generateForeign(): void
    {
        if (self::$foreignPrivateKey !== null) {
            return;
        }

        [self::$foreignPrivateKey, self::$foreignPublicKey] = self::keypair();
    }

    /**
     * @return array{0: string, 1: string} Private and public key, PEM encoded.
     */
    private static function keypair(): array
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($key === false || $details === false || !openssl_pkey_export($key, $pem)) {
            throw new \RuntimeException('Unable to generate an RSA keypair for the test suite.');
        }

        return [$pem, (string) $details['key']];
    }
}

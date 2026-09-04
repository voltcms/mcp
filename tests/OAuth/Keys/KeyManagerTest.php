<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Keys;

use VoltCMS\MCP\OAuth\Keys\KeyManager;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

/**
 * Key generation, permissions and rotation.
 *
 * The two that matter most are the mode of the private key — a signing key any other account on a
 * shared host can read is not a secret — and that a rotation keeps publishing the retired public
 * key until the tokens it signed have expired, because a rotation that did not would reject every
 * live token and log every client out.
 */
final class KeyManagerTest extends RepositoryTestCase
{
    public function testGeneratesAKeypairThatWasNotThere(): void
    {
        $this->assertTrue($this->keys()->ensureKeyPair());
        $this->assertFileExists($this->configuration->privateKeyPath);
        $this->assertFileExists($this->configuration->publicKeyPath);
    }

    public function testDoesNotRegenerateAKeypairThatAlreadyExists(): void
    {
        $keys = $this->keys();
        $keys->ensureKeyPair();

        $this->assertFalse($keys->ensureKeyPair());
    }

    public function testTheGeneratedKeypairIsStable(): void
    {
        $keys = $this->keys();
        $first = $keys->publicKeyPem();

        $this->assertSame($first, $this->keys()->publicKeyPem());
    }

    public function testThePrivateKeyIsReadableOnlyByItsOwner(): void
    {
        $this->keys()->ensureKeyPair();

        $this->assertSame('0600', substr(sprintf('%o', fileperms($this->configuration->privateKeyPath)), -4));
    }

    public function testTheKeyDirectoryIsGivenADenyAllHtaccess(): void
    {
        $this->keys()->ensureKeyPair();

        $this->assertFileExists(dirname($this->configuration->privateKeyPath) . '/.htaccess');
    }

    public function testTheGeneratedPrivateKeyIsUsableForSigning(): void
    {
        $key = openssl_pkey_get_private($this->keys()->privateKey()->getKeyContents());

        $this->assertNotFalse($key);
    }

    // --- Identifiers ---

    public function testTheKeyIdIsTheRfc7638ThumbprintOfThePublicKey(): void
    {
        $keys = $this->keys();

        $this->assertSame(KeyManager::thumbprint($keys->publicKeyPem()), $keys->keyId());
    }

    public function testTheKeyIdIsBase64Url(): void
    {
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $this->keys()->keyId());
    }

    // --- JWKS ---

    public function testTheJwksPublishesTheCurrentKey(): void
    {
        $keys = $this->keys();
        $jwks = $keys->jwks();

        $this->assertSame($keys->keyId(), $jwks['keys'][0]['kid']);
    }

    public function testTheJwksEntryDeclaresRs256Signing(): void
    {
        $jwk = $this->keys()->jwks()['keys'][0];

        $this->assertSame('RSA', $jwk['kty']);
        $this->assertSame('sig', $jwk['use']);
        $this->assertSame('RS256', $jwk['alg']);
    }

    public function testTheJwksCarriesNoPrivateMaterial(): void
    {
        $jwk = $this->keys()->jwks()['keys'][0];

        $this->assertSame(['kty', 'n', 'e', 'use', 'alg', 'kid'], array_keys($jwk));
    }

    // --- Rotation ---

    public function testRotationReplacesTheSigningKey(): void
    {
        $keys   = $this->keys();
        $before = $keys->keyId();


        $this->assertNotSame($before, $keys->rotate());
    }

    public function testRotationKeepsPublishingTheRetiredKey(): void
    {
        $keys    = $this->keys();
        $retired = $keys->keyId();

        $keys->rotate();

        $this->assertContains($retired, array_column($keys->jwks()['keys'], 'kid'));
    }

    public function testTheRetiredKeyStaysAvailableForVerification(): void
    {
        $keys       = $this->keys();
        $retiredPem = $keys->publicKeyPem();

        $keys->rotate();

        $this->assertContains($retiredPem, $keys->verificationKeys());
    }

    public function testTheCurrentKeyIsListedFirstForVerification(): void
    {
        $keys = $this->keys();
        $keys->ensureKeyPair();
        $keys->rotate();

        $this->assertSame($keys->publicKeyPem(), $keys->verificationKeys()[0]);
    }

    public function testARetiredKeyIsDroppedOnceTheTokensItSignedHaveExpired(): void
    {
        $keys = $this->keys();
        $keys->ensureKeyPair();
        $keys->rotate(new \DateTimeImmutable('2026-01-01 12:00:00'));

        $this->assertSame(1, $keys->purgeRetiredKeys(new \DateTimeImmutable('2026-01-01 14:00:00')));
        $this->assertCount(1, $keys->jwks()['keys']);
    }

    public function testARetiredKeyIsNotDroppedWhileItsTokensCouldStillBeLive(): void
    {
        $keys = $this->keys();
        $keys->ensureKeyPair();
        $keys->rotate(new \DateTimeImmutable('2026-01-01 12:00:00'));

        $this->assertSame(0, $keys->purgeRetiredKeys(new \DateTimeImmutable('2026-01-01 12:30:00')));
    }

    public function testRotatingTwiceKeepsBothRetiredKeys(): void
    {
        $keys = $this->keys();
        $keys->ensureKeyPair();
        $keys->rotate();
        $keys->rotate();

        $this->assertCount(3, $keys->jwks()['keys']);
    }

    /**
     * A server that has never generated a key has nothing to retire, so the first rotation is a
     * generation and publishes exactly one key. Rotating before `ensureKeyPair()` is not the
     * expected order — `OAuthServer` ensures the pair in its constructor — but it must not leave a
     * key set with a phantom entry in it.
     */
    public function testRotatingBeforeAnythingExistsPublishesOnlyTheNewKey(): void
    {
        $keys = $this->keys();
        $keys->rotate();

        $this->assertCount(1, $keys->jwks()['keys']);
    }

    private function keys(): KeyManager
    {
        return new KeyManager($this->configuration);
    }
}

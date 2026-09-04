<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Entities;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Entities\ResourceBoundAccessToken;
use VoltCMS\MCP\OAuth\Entities\Scope;
use VoltCMS\MCP\Tests\Support\TestKeys;

/**
 * UPGRADE TRIPWIRE — PLAN.md §4.2.
 *
 * `testTheAudienceIsTheResourceAndNotTheClient` is the whole reason this entity exists instead of
 * league's `AccessTokenTrait`. If it fails after a dependency upgrade, tokens minted here have
 * become replayable at any other server the same client talks to. That is a security regression;
 * fix the entity, do not relax the test.
 */
final class ResourceBoundAccessTokenTest extends TestCase
{
    private const ISSUER   = 'https://example.com';
    private const RESOURCE = 'https://example.com/mcp';

    public function testTheAudienceIsTheResourceAndNotTheClient(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame([self::RESOURCE], $claims->get('aud'));
    }

    public function testCarriesTheClientIdentifierAsItsOwnClaim(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame('claude-desktop', $claims->get('client_id'));
    }

    public function testIsIssuedByTheConfiguredIssuer(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame(self::ISSUER, $claims->get('iss'));
    }

    public function testUsesTheTokenIdentifierAsTheJwtId(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame('token-identifier', $claims->get('jti'));
    }

    public function testTheSubjectIsTheUser(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame('jannis', $claims->get('sub'));
    }

    public function testTheSubjectFallsBackToTheClientWhenThereIsNoUser(): void
    {
        $token = new ResourceBoundAccessToken(self::ISSUER, self::RESOURCE);
        $token->setIdentifier('token-identifier');
        $token->setClient(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));
        $token->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));
        $token->setPrivateKey(new CryptKey(TestKeys::privateKeyPem()));

        $this->assertSame('claude-desktop', $this->claims($token->toString())->get('sub'));
    }

    public function testCarriesItsScopes(): void
    {
        $claims = $this->claims($this->token());

        $this->assertSame(['mcp:read', 'mcp:write'], $claims->get('scopes'));
    }

    public function testExpiresAtTheGivenTime(): void
    {
        $expiry = new \DateTimeImmutable('2026-06-01T12:00:00+00:00');
        $claims = $this->claims($this->token($expiry));

        $this->assertSame('2026-06-01T12:00:00+00:00', $claims->get('exp')->format(\DATE_ATOM));
    }

    public function testRefusesToSerialiseWithoutAPrivateKey(): void
    {
        $token = new ResourceBoundAccessToken(self::ISSUER, self::RESOURCE);
        $token->setIdentifier('token-identifier');
        $token->setClient(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));
        $token->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionCode(ResourceBoundAccessToken::EXCEPTION_PRIVATE_KEY_MISSING);

        $token->toString();
    }

    // --- Helpers ---

    private function token(?\DateTimeImmutable $expiry = null): string
    {
        $token = new ResourceBoundAccessToken(self::ISSUER, self::RESOURCE);
        $token->setIdentifier('token-identifier');
        $token->setClient(new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']));
        $token->setUserIdentifier('jannis');
        $token->addScope(new Scope('mcp:read'));
        $token->addScope(new Scope('mcp:write'));
        $token->setExpiryDateTime($expiry ?? new \DateTimeImmutable('+1 hour'));
        $token->setPrivateKey(new CryptKey(TestKeys::privateKeyPem()));

        return $token->toString();
    }

    private function claims(string $jwt): \Lcobucci\JWT\Token\DataSet
    {
        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertInstanceOf(UnencryptedToken::class, $parsed);

        return $parsed->claims();
    }
}

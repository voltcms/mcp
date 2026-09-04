<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use Defuse\Crypto\Crypto;
use Lcobucci\JWT\Configuration as JwtConfiguration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;
use VoltCMS\MCP\Tests\Support\TestKeys;

/**
 * RFC 7009 revocation, which league ships nothing for.
 *
 * The tests that matter are the ones about the grant rather than the token: revoking either end
 * must end both, because a revocation that leaves the refresh token alive gets a fresh access
 * token minutes later and looks, from the outside, like it did nothing at all.
 *
 * The two documented deviations from the RFC are covered too: a token belonging to another client
 * is answered 200 and not revoked rather than refused, so the endpoint cannot be used to ask
 * whether a token exists.
 */
final class RevokeEndpointTest extends EndpointTestCase
{
    // --- Revoking a refresh token ---

    public function testRevokingARefreshTokenAnswersOk(): void
    {
        $issued = $this->issueTokens();

        $this->assertSame(Response::STATUS_OK, $this->revokeToken((string) $issued['refresh_token'])->status);
    }

    public function testARevokedRefreshTokenCannotBeRefreshed(): void
    {
        $issued = $this->issueTokens();
        $this->revokeToken((string) $issued['refresh_token']);

        $refreshed = $this->postToken([
            'grant_type'    => 'refresh_token',
            'client_id'     => self::CLIENT_ID,
            'refresh_token' => $issued['refresh_token'],
        ])->decodedBody();

        $this->assertSame('invalid_grant', $refreshed['error'] ?? null);
    }

    public function testRevokingARefreshTokenAlsoRevokesTheAccessTokenIssuedWithIt(): void
    {
        $issued = $this->issueTokens();
        $this->revokeToken((string) $issued['refresh_token']);

        $this->assertTrue($this->accessTokens->isAccessTokenRevoked($this->tokenId((string) $issued['access_token'])));
    }

    // --- Revoking an access token ---

    public function testRevokingAnAccessTokenMarksItRevokedInTheStore(): void
    {
        $issued = $this->issueTokens();
        $this->revokeToken((string) $issued['access_token']);

        $this->assertTrue($this->accessTokens->isAccessTokenRevoked($this->tokenId((string) $issued['access_token'])));
    }

    public function testRevokingAnAccessTokenAlsoEndsTheRefreshPath(): void
    {
        $issued = $this->issueTokens();
        $this->revokeToken((string) $issued['access_token']);

        $refreshed = $this->postToken([
            'grant_type'    => 'refresh_token',
            'client_id'     => self::CLIENT_ID,
            'refresh_token' => $issued['refresh_token'],
        ])->decodedBody();

        $this->assertSame('invalid_grant', $refreshed['error'] ?? null);
    }

    // --- Tokens that are not this client's ---

    public function testAnotherClientsRefreshTokenIsNotRevoked(): void
    {
        $issued = $this->issueTokens();

        $this->revokeToken((string) $issued['refresh_token'], self::CONFIDENTIAL_ID, self::CLIENT_SECRET);

        $tokenId = $this->refreshTokenId((string) $issued['refresh_token']);

        $this->assertFalse($this->refreshTokens->isRefreshTokenRevoked($tokenId));
    }

    public function testAnotherClientsRefreshTokenIsStillAnsweredOk(): void
    {
        $issued = $this->issueTokens();

        $response = $this->revokeToken((string) $issued['refresh_token'], self::CONFIDENTIAL_ID, self::CLIENT_SECRET);

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    public function testAnotherClientsAccessTokenIsNotRevoked(): void
    {
        $issued = $this->issueTokens();

        $this->revokeToken((string) $issued['access_token'], self::CONFIDENTIAL_ID, self::CLIENT_SECRET);

        $this->assertFalse($this->accessTokens->isAccessTokenRevoked($this->tokenId((string) $issued['access_token'])));
    }

    // --- Tokens that are not tokens ---

    public function testAnUnrecognisableTokenIsAnsweredOk(): void
    {
        $this->assertSame(Response::STATUS_OK, $this->revokeToken('not-a-token-at-all')->status);
    }

    public function testAnAccessTokenSignedByAnotherKeyIsNotRevoked(): void
    {
        $issued = $this->issueTokens();
        $forged = $this->reSign((string) $issued['access_token']);

        $this->revokeToken($forged);

        $this->assertFalse($this->accessTokens->isAccessTokenRevoked($this->tokenId((string) $issued['access_token'])));
    }

    // --- Client authentication ---

    public function testAnUnknownClientIsRefused(): void
    {
        $issued = $this->issueTokens();

        $response = $this->revokeToken((string) $issued['refresh_token'], 'never-registered');

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testAConfidentialClientWithNoSecretIsRefused(): void
    {
        $issued = $this->issueTokens();

        $response = $this->revokeToken((string) $issued['refresh_token'], self::CONFIDENTIAL_ID);

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testAConfidentialClientMayAuthenticateWithBasicAuth(): void
    {
        $issued = $this->issueTokens();

        $response = $this->revoke->handle(new Request(
            'POST',
            '/oauth/revoke',
            [],
            ['token' => $issued['refresh_token']],
            ['Authorization' => 'Basic ' . base64_encode(self::CONFIDENTIAL_ID . ':' . self::CLIENT_SECRET)],
        ));

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    public function testAMissingTokenParameterIsRefused(): void
    {
        $response = $this->revoke->handle(new Request('POST', '/oauth/revoke', [], ['client_id' => self::CLIENT_ID]));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testAGetIsRefusedWithTheAllowedMethod(): void
    {
        $response = $this->revoke->handle(new Request('GET', '/oauth/revoke'));

        $this->assertSame(Response::STATUS_METHOD_NOT_ALLOWED, $response->status);
        $this->assertSame('POST', $response->header('Allow'));
    }

    public function testNothingIsWrittenToTheOutputBuffer(): void
    {
        $issued = $this->issueTokens();

        ob_start();
        $this->revokeToken((string) $issued['refresh_token']);
        $emitted = (string) ob_get_clean();

        $this->assertSame('', $emitted);
    }

    // --- Helpers ---

    private function revokeToken(string $token, string $clientId = self::CLIENT_ID, ?string $secret = null): Response
    {
        $body = ['token' => $token, 'client_id' => $clientId];

        if ($secret !== null) {
            $body['client_secret'] = $secret;
        }

        return $this->revoke->handle(new Request('POST', '/oauth/revoke', [], $body));
    }

    private function tokenId(string $jwt): string
    {
        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertInstanceOf(UnencryptedToken::class, $parsed);

        return (string) $parsed->claims()->get('jti');
    }

    /**
     * The identifier inside league's encrypted refresh token, read the way the endpoint reads it.
     */
    private function refreshTokenId(string $refreshToken): string
    {
        $payload = json_decode(
            Crypto::decryptWithPassword($refreshToken, $this->configuration->encryptionKey),
            true,
        );

        return (string) $payload['refresh_token_id'];
    }

    /**
     * The same claims, signed by a key this server has never seen — a token that looks right to
     * anyone who does not check the signature.
     */
    private function reSign(string $jwt): string
    {
        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);

        $this->assertInstanceOf(UnencryptedToken::class, $parsed);

        $configuration = JwtConfiguration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText(TestKeys::foreignPrivateKeyPem()),
            InMemory::plainText('empty', 'empty'),
        );

        $claims = $parsed->claims();

        $token = $configuration->builder()
            ->issuedBy((string) $claims->get('iss'))
            ->permittedFor(...$claims->get('aud'))
            ->identifiedBy((string) $claims->get('jti'))
            ->issuedAt($claims->get('iat'))
            ->canOnlyBeUsedAfter($claims->get('nbf'))
            ->expiresAt($claims->get('exp'))
            ->relatedTo((string) $claims->get('sub'))
            ->withClaim('client_id', $claims->get('client_id'))
            ->withClaim('scopes', $claims->get('scopes'))
            ->getToken($configuration->signer(), $configuration->signingKey());

        return $token->toString();
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Entities;

use Lcobucci\JWT\Configuration as JwtConfiguration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * An access token whose `aud` claim is the protected RESOURCE, not the client.
 *
 * This class exists because league's `AccessTokenTrait` cannot be made to do that.
 * `convertToJWT()` is `private`, and it hard-codes `->permittedFor($this->getClient()
 * ->getIdentifier())` — so a token minted by this server carries `aud = <client id>`, which is
 * the same value at every server that client talks to, and therefore replayable at any of them.
 * RFC 8707 and the MCP authorization spec want the audience to be this endpoint's canonical URL.
 * Implementing `AccessTokenEntityInterface` directly is the only way to reach the claim set.
 *
 * That is why the trait is NOT used here, and why replacing this class with
 * `use AccessTokenTrait;` would silently re-open cross-server token replay. See PLAN.md §4.2.
 *
 * The client identifier is kept as the `client_id` claim (RFC 9068) so nothing is lost by moving
 * the audience, and `iss` is added, which league does not set at all.
 */
final class ResourceBoundAccessToken implements AccessTokenEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;

    public const EXCEPTION_PRIVATE_KEY_MISSING = 2001;
    public const EXCEPTION_PRIVATE_KEY_EMPTY   = 2002;

    private ?CryptKeyInterface $privateKey = null;

    public function __construct(
        private readonly string $issuer,
        private readonly string $resource,
    ) {
    }

    public function setPrivateKey(
        #[\SensitiveParameter]
        CryptKeyInterface $privateKey,
    ): void {
        $this->privateKey = $privateKey;
    }

    public function toString(): string
    {
        $privateKey = $this->privateKey;

        if ($privateKey === null) {
            throw new \RuntimeException(
                'No private key has been set on the access token.',
                self::EXCEPTION_PRIVATE_KEY_MISSING,
            );
        }

        $contents = $privateKey->getKeyContents();

        if ($contents === '') {
            throw new \RuntimeException('The private key is empty.', self::EXCEPTION_PRIVATE_KEY_EMPTY);
        }

        $jwt = JwtConfiguration::forAsymmetricSigner(
            new Sha256(),
            InMemory::plainText($contents, $privateKey->getPassPhrase() ?? ''),
            // Verification happens in the resource server, never here; league passes the same
            // placeholder for the same reason.
            InMemory::plainText('empty', 'empty'),
        );

        $now = new \DateTimeImmutable();

        return $jwt->builder()
            ->issuedBy($this->issuer)
            ->permittedFor($this->resource)
            ->identifiedBy($this->getIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->subjectIdentifier())
            ->withClaim('client_id', $this->getClient()->getIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($jwt->signer(), $jwt->signingKey())
            ->toString();
    }

    /**
     * A client-credentials token has no user; its subject is the client itself. league resolves
     * the subject the same way.
     */
    private function subjectIdentifier(): string
    {
        return $this->getUserIdentifier() ?? $this->getClient()->getIdentifier();
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Tokens;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;

/**
 * Turns a bearer string back into claims, or into nothing.
 *
 * The audience check is the load-bearing one and the reason this class is not just a parser.
 * `ResourceBoundAccessToken` mints `aud = <this MCP endpoint>` precisely so a token cannot be
 * replayed at another server; verifying that audience on the way in is the other half of the same
 * guarantee, and an implementation that only checked the signature would accept a perfectly valid
 * token issued by this same server for a different resource. See PLAN.md §4.2.
 *
 * Several public keys are accepted so a key rotation does not invalidate every live token at once:
 * the retired key stays in the list until the last token it signed has expired. Order does not
 * matter; the first key that verifies wins.
 *
 * Expiry is NOT checked here — see `AccessTokenClaims` for why.
 */
final class AccessTokenVerifier
{
    public const EXCEPTION_NO_VERIFICATION_KEY = 7001;

    private const CLAIM_CLIENT_ID = 'client_id';
    private const CLAIM_SCOPES    = 'scopes';

    private readonly string $issuer;
    private readonly string $resource;

    /** @var list<string> PEM-encoded public keys. */
    private readonly array $publicKeys;

    /**
     * @param list<string> $publicKeys PEM-encoded, current key first.
     *
     * @throws \InvalidArgumentException if there is nothing to verify against.
     */
    public function __construct(string $issuer, string $resource, array $publicKeys)
    {
        $keys = array_values(array_filter($publicKeys, static fn (string $key): bool => trim($key) !== ''));

        if ($keys === []) {
            throw new \InvalidArgumentException(
                'At least one public key is required; a verifier with none would refuse every token.',
                self::EXCEPTION_NO_VERIFICATION_KEY,
            );
        }

        $this->issuer     = $issuer;
        $this->resource   = $resource;
        $this->publicKeys = $keys;
    }

    /**
     * The token's claims, or null if it is not a token this server minted for this resource.
     *
     * Null covers every kind of failure — unparseable, wrong signature, wrong issuer, wrong
     * audience, missing claims — on purpose: a caller that could tell them apart would be an
     * oracle, and none of the differences change what the caller does next.
     */
    public function verify(string $jwt): ?AccessTokenClaims
    {
        try {
            $token = (new Parser(new JoseEncoder()))->parse($jwt);
        } catch (\Throwable) {
            return null;
        }

        if (!$token instanceof UnencryptedToken || !$this->signatureIsOurs($token)) {
            return null;
        }

        $claims = $token->claims();

        $identifier = $claims->get(RegisteredClaims::ID);
        $clientId   = $claims->get(self::CLAIM_CLIENT_ID);
        $subject    = $claims->get(RegisteredClaims::SUBJECT);
        $expiresAt  = $claims->get(RegisteredClaims::EXPIRATION_TIME);
        $scopes     = $claims->get(self::CLAIM_SCOPES, []);

        if (!is_string($identifier) || !is_string($clientId) || !is_string($subject)) {
            return null;
        }

        if (!$expiresAt instanceof \DateTimeImmutable) {
            return null;
        }

        return new AccessTokenClaims(
            $identifier,
            $clientId,
            $subject,
            self::scopeList($scopes),
            $expiresAt,
        );
    }

    private function signatureIsOurs(UnencryptedToken $token): bool
    {
        $signer    = new Sha256();
        $validator = new Validator();

        foreach ($this->publicKeys as $publicKey) {
            $valid = $validator->validate(
                $token,
                new SignedWith($signer, InMemory::plainText($publicKey)),
                new IssuedBy($this->issuer),
                new PermittedFor($this->resource),
            );

            if ($valid) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private static function scopeList(mixed $scopes): array
    {
        if (is_string($scopes)) {
            $scopes = explode(' ', $scopes);
        }

        if (!is_array($scopes)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $scope): string => is_string($scope) ? $scope : '', $scopes),
            static fn (string $scope): bool => $scope !== '',
        ));
    }
}

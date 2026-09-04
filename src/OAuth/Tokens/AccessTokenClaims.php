<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Tokens;

/**
 * The claims of a verified access token, after the signature, issuer and audience have been
 * checked.
 *
 * Constructing one is a statement that the token was genuinely minted by this server for this
 * resource. What it is NOT is a statement that the token is still good: expiry, revocation and the
 * state of the account behind it are all checked afterwards, by whoever holds the store and the
 * identity provider. Keeping those apart is what lets the revocation endpoint act on an expired
 * token and the MCP bridge refuse a live one.
 *
 * Immutable.
 */
final class AccessTokenClaims
{
    public readonly string $identifier;
    public readonly string $clientId;
    public readonly string $subject;

    /** @var list<string> */
    public readonly array $scopes;

    public readonly \DateTimeImmutable $expiresAt;

    /**
     * @param list<string> $scopes
     */
    public function __construct(
        string $identifier,
        string $clientId,
        string $subject,
        array $scopes,
        \DateTimeImmutable $expiresAt,
    ) {
        $this->identifier = $identifier;
        $this->clientId   = $clientId;
        $this->subject    = $subject;
        $this->scopes     = array_values($scopes);
        $this->expiresAt  = $expiresAt;
    }

    public function hasExpired(?\DateTimeImmutable $now = null): bool
    {
        return $this->expiresAt <= ($now ?? new \DateTimeImmutable());
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Bridge;

use Mcp\Server\Transport\Http\OAuth\AuthorizationResult;
use Mcp\Server\Transport\Http\OAuth\AuthorizationTokenValidatorInterface;
use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\OAuth\Repositories\AccessTokenRepository;
use VoltCMS\MCP\OAuth\Tokens\AccessTokenVerifier;

/**
 * The join: `mcp/sdk`'s bearer-token seam, answered with the tokens `league/oauth2-server` minted.
 *
 * This is the class the whole package exists to make possible. `mcp/sdk` ships
 * `JwtTokenValidator`, which fetches a JWKS over the network from an external identity provider —
 * sensible when there is one, and absurd when the authorization server is the same PHP process
 * answering this request. This validator reads the key off disk and the record out of the store,
 * makes no network call at all, and therefore also satisfies "no network in tests, ever".
 *
 * ## What it checks, in order, and why each one is here
 *
 * 1. **Signature, issuer and audience** — `AccessTokenVerifier`. The audience check is the RFC 8707
 *    half of PLAN.md §4.2: a token minted by this same server for a different resource is refused.
 * 2. **Expiry.**
 * 3. **Revocation, against the store.** This is a lookup per request, and it is deliberate: it is
 *    what makes revoking an access token take effect now rather than at expiry. See
 *    docs/decisions/0005-validation-reads-the-store.md for the cost and the measurement.
 * 4. **The account, read fresh** — `IdentityProviderInterface::findUser()`. A user deactivated or
 *    deleted after the token was issued fails here.
 * 5. **The scopes, against the live policy.** A role removed after issue narrows the token now.
 *    The token's own scope list is never trusted on its own: it is the intersection of what the
 *    token says and what the account may currently grant.
 *
 * Every refusal is the same shape — 401 `invalid_token` with a description that names the class of
 * failure, never which check failed for which token. A caller that could tell "expired" from
 * "revoked" from "no such user" apart has a small oracle over other people's tokens.
 */
final class McpTokenValidator implements AuthorizationTokenValidatorInterface
{
    // --- Attributes attached to the request on success ---

    public const ATTRIBUTE_SUBJECT   = 'oauth.subject';
    public const ATTRIBUTE_CLIENT_ID = 'oauth.client_id';
    public const ATTRIBUTE_SCOPES    = 'oauth.scopes';
    public const ATTRIBUTE_TOKEN_ID  = 'oauth.token_id';
    public const ATTRIBUTE_IDENTITY  = 'mcp.identity';

    private const INVALID_TOKEN = 'invalid_token';

    /** @var list<string> */
    private readonly array $requiredScopes;

    /**
     * @param list<string> $requiredScopes Scopes every request must carry, whatever it is asking for.
     */
    public function __construct(
        private readonly AccessTokenVerifier $verifier,
        private readonly AccessTokenRepository $accessTokens,
        private readonly IdentityProviderInterface $identities,
        private readonly ScopePolicyInterface $scopePolicy,
        array $requiredScopes = [],
    ) {
        $this->requiredScopes = array_values($requiredScopes);
    }

    public function validate(string $accessToken): AuthorizationResult
    {
        $claims = $this->verifier->verify($accessToken);

        if ($claims === null || $claims->hasExpired()) {
            return AuthorizationResult::unauthorized(self::INVALID_TOKEN, 'The access token is not valid for this resource.');
        }

        if ($this->accessTokens->isAccessTokenRevoked($claims->identifier)) {
            return AuthorizationResult::unauthorized(self::INVALID_TOKEN, 'The access token is not valid for this resource.');
        }

        $identity = $this->identities->findUser($claims->subject);

        if ($identity === null) {
            return AuthorizationResult::unauthorized(self::INVALID_TOKEN, 'The access token is not valid for this resource.');
        }

        $grantable = $this->scopePolicy->grantableFor($identity);
        $effective = array_values(array_filter(
            $claims->scopes,
            static fn (string $scope): bool => in_array($scope, $grantable, true),
        ));

        $missing = array_values(array_diff($this->requiredScopes, $effective));

        if ($effective === [] || $missing !== []) {
            return AuthorizationResult::forbidden(
                'insufficient_scope',
                'The account behind this token no longer grants the scopes it needs.',
                $this->requiredScopes === [] ? null : $this->requiredScopes,
            );
        }

        return AuthorizationResult::allow([
            self::ATTRIBUTE_SUBJECT   => $identity->identifier,
            self::ATTRIBUTE_CLIENT_ID => $claims->clientId,
            self::ATTRIBUTE_SCOPES    => $effective,
            self::ATTRIBUTE_TOKEN_ID  => $claims->identifier,
            self::ATTRIBUTE_IDENTITY  => $identity,
        ]);
    }
}

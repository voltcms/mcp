<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\ScopePolicyInterface;
use VoltCMS\MCP\OAuth\Entities\Scope;

/**
 * Scopes come from configuration, so this repository has no store behind it.
 *
 * `finalizeScopes()` is the last point at which a token's scopes can be narrowed, and it is where
 * SECURITY.md's promise — *a token can never carry a scope its granting user's roles do not
 * support* — is actually kept for every grant.
 *
 * The authorize endpoint narrows the request before anyone is asked to consent, which covers the
 * authorization-code flow. It does not cover the REFRESH flow: a refresh happens with no browser,
 * no consent screen and no authorize endpoint, so a user demoted after they consented would keep
 * being handed the scopes they had at the time, for as long as they kept refreshing. This is the
 * only place both flows pass through.
 *
 * With no identity provider or policy given it filters to the configured set alone — defence in
 * depth against a grant handing through a scope nobody configured, and nothing more.
 */
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(
        private readonly Configuration $configuration,
        private readonly ?IdentityProviderInterface $identities = null,
        private readonly ?ScopePolicyInterface $scopePolicy = null,
    ) {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $this->configuration->scopeIsSupported($identifier) ? new Scope($identifier) : null;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     *
     * @return ScopeEntityInterface[]
     *
     * @throws OAuthServerException if the account behind the grant is gone or grants nothing.
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        string|null $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $configured = [];

        foreach ($scopes as $scope) {
            if ($this->configuration->scopeIsSupported($scope->getIdentifier())) {
                $configured[] = $scope;
            }
        }

        if ($this->identities === null || $this->scopePolicy === null) {
            return $configured;
        }

        if ($userIdentifier === null || $userIdentifier === '') {
            return $configured;
        }

        $identity = $this->identities->findUser($userIdentifier);

        if ($identity === null) {
            // Deactivated or deleted since the grant was made. Refusing here is what stops the
            // refresh path outliving the account.
            throw OAuthServerException::invalidGrant('The account this grant belongs to is no longer active.');
        }

        $grantable = $this->scopePolicy->grantableFor($identity);
        $granted   = [];

        foreach ($configured as $scope) {
            if (in_array($scope->getIdentifier(), $grantable, true)) {
                $granted[] = $scope;
            }
        }

        if ($granted === []) {
            throw OAuthServerException::invalidGrant('The account this grant belongs to grants none of its scopes.');
        }

        return $granted;
    }
}

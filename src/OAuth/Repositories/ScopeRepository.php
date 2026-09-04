<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use VoltCMS\MCP\Configuration;
use VoltCMS\MCP\OAuth\Entities\Scope;

/**
 * Scopes come from configuration, so this repository has no store behind it.
 *
 * `finalizeScopes()` is the last point at which a token's scopes can be narrowed, and it is where
 * the role-to-scope policy belongs. Until P5 lands `ScopePolicy`, it filters to the configured
 * set only: that is defence in depth against a grant handing through a scope nobody configured,
 * NOT the promise in SECURITY.md that a token can never carry a scope its user's roles do not
 * support. Wiring the policy in here is P5's first job.
 */
final class ScopeRepository implements ScopeRepositoryInterface
{
    public function __construct(private readonly Configuration $configuration)
    {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return $this->configuration->scopeIsSupported($identifier) ? new Scope($identifier) : null;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     *
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        string|null $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        $finalized = [];

        foreach ($scopes as $scope) {
            if ($this->configuration->scopeIsSupported($scope->getIdentifier())) {
                $finalized[] = $scope;
            }
        }

        return $finalized;
    }
}

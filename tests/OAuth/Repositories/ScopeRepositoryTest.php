<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Repositories;

use VoltCMS\MCP\OAuth\Entities\Client;
use VoltCMS\MCP\OAuth\Entities\Scope;
use VoltCMS\MCP\OAuth\Repositories\ScopeRepository;
use VoltCMS\MCP\Tests\Support\RepositoryTestCase;

final class ScopeRepositoryTest extends RepositoryTestCase
{
    private ScopeRepository $repository;

    protected function setUp(): void
    {
        parent::setUp();

        $this->repository = new ScopeRepository($this->configuration);
    }

    public function testResolvesAConfiguredScope(): void
    {
        $scope = $this->repository->getScopeEntityByIdentifier('mcp:read');

        $this->assertNotNull($scope);
        $this->assertSame('mcp:read', $scope->getIdentifier());
    }

    public function testDoesNotResolveAnUnconfiguredScope(): void
    {
        $this->assertNull($this->repository->getScopeEntityByIdentifier('mcp:admin'));
    }

    public function testKeepsConfiguredScopesWhenFinalising(): void
    {
        $finalized = $this->repository->finalizeScopes(
            [new Scope('mcp:read'), new Scope('mcp:write')],
            'authorization_code',
            $this->client(),
            'jannis',
        );

        $this->assertSame(['mcp:read', 'mcp:write'], array_map(
            static fn ($scope): string => $scope->getIdentifier(),
            $finalized,
        ));
    }

    public function testDropsAnUnconfiguredScopeWhenFinalising(): void
    {
        $finalized = $this->repository->finalizeScopes(
            [new Scope('mcp:read'), new Scope('mcp:admin')],
            'authorization_code',
            $this->client(),
            'jannis',
        );

        $this->assertSame(['mcp:read'], array_map(
            static fn ($scope): string => $scope->getIdentifier(),
            $finalized,
        ));
    }

    private function client(): Client
    {
        return new Client('claude-desktop', 'Claude Desktop', ['https://claude.ai/callback']);
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Identity;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\Identity\ScopePolicy;

/**
 * The role-to-scope table. SECURITY.md promises that a token can never carry a scope its granting
 * user's roles do not support, and this is the class that decides it — so the interesting tests
 * are the ones about what is NOT granted.
 */
final class ScopePolicyTest extends TestCase
{
    public function testGrantsTheScopesOfTheRoleTheUserHas(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:read', 'mcp:write']]);

        $this->assertSame(['mcp:read', 'mcp:write'], $policy->grantableFor($this->identity(['editor'])));
    }

    public function testGrantsNothingForARoleThatIsNotInTheTable(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:write']]);

        $this->assertSame([], $policy->grantableFor($this->identity(['subscriber'])));
    }

    public function testGrantsNothingToAUserWithNoRoles(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:write']]);

        $this->assertSame([], $policy->grantableFor($this->identity([])));
    }

    public function testRoleNamesAreMatchedCaseSensitively(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:write']]);

        $this->assertSame([], $policy->grantableFor($this->identity(['Editor'])));
    }

    public function testUnionsTheScopesOfSeveralRolesWithoutRepeatingOne(): void
    {
        $policy = new ScopePolicy([
            'reader' => ['mcp:read'],
            'editor' => ['mcp:read', 'mcp:write'],
        ]);

        $this->assertSame(['mcp:read', 'mcp:write'], $policy->grantableFor($this->identity(['reader', 'editor'])));
    }

    public function testScopesForEveryoneAreGrantedWithoutARole(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:write']], ['mcp:read']);

        $this->assertSame(['mcp:read'], $policy->grantableFor($this->identity([])));
    }

    public function testARoleAddsToTheScopesEveryoneHas(): void
    {
        $policy = new ScopePolicy(['editor' => ['mcp:write']], ['mcp:read']);

        $this->assertSame(['mcp:read', 'mcp:write'], $policy->grantableFor($this->identity(['editor'])));
    }

    public function testTheSingleUserShorthandGrantsEverythingToAnyAccount(): void
    {
        $policy = ScopePolicy::everyoneMay(['mcp:read', 'mcp:write']);

        $this->assertSame(['mcp:read', 'mcp:write'], $policy->grantableFor($this->identity([])));
    }

    public function testRefusesAScopeThatIsNotAString(): void
    {
        $this->expectExceptionCode(ScopePolicy::EXCEPTION_SCOPE_MALFORMED);

        /** @phpstan-ignore-next-line deliberately wrong, to prove the refusal */
        new ScopePolicy(['editor' => ['mcp:read', 42]]);
    }

    /**
     * @param list<string> $roles
     */
    private function identity(array $roles): Identity
    {
        return new Identity('jannis', 'Jannis', $roles);
    }
}

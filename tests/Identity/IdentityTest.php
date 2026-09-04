<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Identity;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Identity\Identity;

/**
 * The identity value object. Small, but it is what a token's `sub` and every scope decision are
 * built from, so its refusals are worth stating.
 */
final class IdentityTest extends TestCase
{
    public function testRefusesAnEmptyIdentifier(): void
    {
        $this->expectExceptionCode(Identity::EXCEPTION_IDENTIFIER_REQUIRED);

        new Identity('   ');
    }

    public function testRefusesARoleThatIsNotAString(): void
    {
        $this->expectExceptionCode(Identity::EXCEPTION_ROLE_MALFORMED);

        /** @phpstan-ignore-next-line deliberately wrong, to prove the refusal */
        new Identity('jannis', 'Jannis', ['editor', 42]);
    }

    public function testFallsBackToTheIdentifierWhenThereIsNoDisplayName(): void
    {
        $this->assertSame('jannis', (new Identity('jannis'))->displayName);
    }

    public function testDropsADuplicatedRole(): void
    {
        $identity = new Identity('jannis', 'Jannis', ['editor', 'editor']);

        $this->assertSame(['editor'], $identity->roles);
    }

    public function testAnswersHasRoleForARoleItWasGiven(): void
    {
        $this->assertTrue((new Identity('jannis', 'Jannis', ['editor']))->hasRole('editor'));
    }

    public function testRoleComparisonIsCaseSensitive(): void
    {
        $this->assertFalse((new Identity('jannis', 'Jannis', ['editor']))->hasRole('Editor'));
    }
}

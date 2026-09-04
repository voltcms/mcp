<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Identity;

use PHPUnit\Framework\TestCase;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Identity\UserAccessIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubSession;
use VoltCMS\MCP\Tests\Support\TempDirectory;
use VoltCMS\MCP\Tests\Support\UserAccessStore;

/**
 * Identity over real `voltcms/useraccess` directories.
 *
 * `findUser()` is the one that carries a security promise: SECURITY.md says a deactivated account
 * or a removed role invalidates a live token now rather than at expiry, and it is only true because
 * this method re-reads the stored record every time it is asked. The deactivation and demotion
 * tests below are that promise; if they break, tokens outlive the accounts behind them.
 */
final class UserAccessIdentityProviderTest extends TestCase
{
    private string $root;
    private UserAccessStore $store;
    private StubSession $session;

    protected function setUp(): void
    {
        parent::setUp();

        $this->root    = TempDirectory::create();
        $this->store   = new UserAccessStore($this->root);
        $this->session = new StubSession();
    }

    protected function tearDown(): void
    {
        TempDirectory::remove($this->root);

        parent::tearDown();
    }

    // --- Lookup ---

    public function testFindsAStoredUserById(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis Rondorf');

        $this->assertSame($user->getId(), $this->provider()->findUser($user->getId())?->identifier);
    }

    public function testCarriesTheDisplayName(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis Rondorf');

        $this->assertSame('Jannis Rondorf', $this->provider()->findUser($user->getId())?->displayName);
    }

    public function testFallsBackToTheUserNameWhenThereIsNoDisplayName(): void
    {
        $user = $this->store->createUser('jannis');

        $this->assertSame('jannis', $this->provider()->findUser($user->getId())?->displayName);
    }

    public function testReportsGroupMembershipAsRoles(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis', ['editors']);

        $this->assertContains('editors', (array) $this->provider()->findUser($user->getId())?->roles);
    }

    public function testAnUnknownIdentifierFindsNobody(): void
    {
        $this->assertNull($this->provider()->findUser('7f0e0e4e-0000-0000-0000-000000000000'));
    }

    // --- The promise ---

    public function testADeactivatedAccountFindsNobody(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis');
        $this->store->deactivate($user->getId());

        $this->assertNull($this->provider()->findUser($user->getId()));
    }

    public function testARoleRemovedAfterTheFactIsGone(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis', ['editors']);
        $this->store->removeFromGroup($user->getId(), 'editors');

        $this->assertNotContains('editors', (array) $this->provider()->findUser($user->getId())?->roles);
    }

    // --- Identifiers that are not identifiers ---

    public function testAnIdentifierContainingATraversalFindsNobody(): void
    {
        $this->store->createUser('jannis', 'Jannis');

        $this->assertNull($this->provider()->findUser('../../../etc/passwd'));
    }

    public function testAnEmptyIdentifierFindsNobody(): void
    {
        $this->assertNull($this->provider()->findUser(''));
    }

    /**
     * The store lowercases an identifier before looking it up, so a differently-cased identifier
     * resolves the same record. The `hash_equals()` re-check afterwards is what refuses it.
     */
    public function testAnIdentifierDifferingOnlyInCaseFindsNobody(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis');

        $this->assertNull($this->provider()->findUser(strtoupper($user->getId())));
    }

    // --- The session ---

    public function testThereIsNoCurrentUserWithoutASession(): void
    {
        $this->store->createUser('jannis', 'Jannis');

        $this->assertNull($this->provider()->currentUser(new Request('GET', '/oauth/authorize')));
    }

    public function testTheCurrentUserIsTheOneTheSessionNames(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis');
        $this->session->logIn($user->getId());

        $this->assertSame($user->getId(), $this->provider()->currentUser(new Request('GET', '/'))?->identifier);
    }

    public function testASessionNamingADeactivatedAccountHasNoCurrentUser(): void
    {
        $user = $this->store->createUser('jannis', 'Jannis');
        $this->session->logIn($user->getId());
        $this->store->deactivate($user->getId());

        $this->assertNull($this->provider()->currentUser(new Request('GET', '/')));
    }

    private function provider(): UserAccessIdentityProvider
    {
        return new UserAccessIdentityProvider($this->store->users, $this->store->groups, $this->session);
    }
}

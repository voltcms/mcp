<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Identity;

use VoltCMS\MCP\Contracts\IdentityProviderInterface;
use VoltCMS\MCP\Contracts\SessionInterface;
use VoltCMS\MCP\Http\Request;
use VoltCMS\UserAccess\Group;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\GroupProviderInterface;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;
use VoltCMS\UserAccess\UserProviderInterface;

/**
 * Identity over `voltcms/useraccess`, concrete.
 *
 * This is the class that keeps `IdentityProviderInterface` off the list of things a consumer has
 * to implement: an application already using useraccess passes its `users/` and `groups/`
 * directories and is finished. PLAN.md §3.1 is explicit that identity is not a seam, because a
 * consumer writing their own identity adapter is a consumer writing their own security-critical
 * code.
 *
 * ## Two things it does not delegate
 *
 * **Group membership is computed here, not through `User::isMemberOf()`.** That method reaches for
 * `GroupProvider::getInstance()` with no arguments, which resolves to whichever singleton happens
 * to have been created first — in a test, or in an application with more than one group
 * directory, that is not necessarily the one this provider was given.
 *
 * **The identifier is validated before it reaches the store, and re-checked after.**
 * `UserProvider::read('id', …)` builds a filesystem path out of the value, so an identifier
 * carrying `../` is a traversal, and it lowercases before looking up, so two identifiers differing
 * only in case resolve to the same record. Token subjects arrive from a signed JWT rather than
 * straight off the wire, which makes this defence in depth rather than the front line — but it is
 * the same class of hazard as PLAN.md §4.8, and it costs a `preg_match` and a `hash_equals`.
 */
final class UserAccessIdentityProvider implements IdentityProviderInterface
{
    /** FileDB names records by UUID; anything outside this set is not an identifier it issued. */
    private const IDENTIFIER_PATTERN = '/^[A-Za-z0-9._-]{1,128}$/';

    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly GroupProviderInterface $groups,
        private readonly SessionInterface $session,
    ) {
    }

    /**
     * The conventional wiring: two directories, useraccess's own singletons, and its session.
     *
     * Note that useraccess's providers ARE singletons — the first call in a process fixes the
     * directories for every later one. That is its design, not ours; an application that needs two
     * of them constructs this class directly.
     */
    public static function overDirectories(string $usersDirectory, string $groupsDirectory): self
    {
        $users  = UserProvider::getInstance(['directory' => $usersDirectory]);
        $groups = GroupProvider::getInstance(['directory' => $groupsDirectory]);

        return new self($users, $groups, new UserAccessSession($users, $groups));
    }

    public function currentUser(Request $request): ?Identity
    {
        $identifier = $this->session->currentUserIdentifier();

        return $identifier === null ? null : $this->findUser($identifier);
    }

    /**
     * Reads the stored record fresh, every time, and returns null for any account that is not
     * usable right now.
     *
     * That null is what makes SECURITY.md's promise true: a token issued an hour ago is only as
     * good as the account behind it is at this moment, so deactivating a user invalidates their
     * live tokens instead of waiting for the TTL.
     */
    public function findUser(string $identifier): ?Identity
    {
        if (preg_match(self::IDENTIFIER_PATTERN, $identifier) !== 1) {
            return null;
        }

        try {
            $user = $this->users->read('id', $identifier);
        } catch (\Throwable) {
            // useraccess throws EXCEPTION_ENTRY_NOT_EXIST rather than returning null.
            return null;
        }

        if (!hash_equals($user->getId(), $identifier) || !$user->isActive()) {
            return null;
        }

        return new Identity($user->getId(), $this->displayName($user), $this->rolesOf($user));
    }

    // --- Helpers ---

    /**
     * @return list<string> The display names of every group this user belongs to.
     */
    private function rolesOf(User $user): array
    {
        $roles = [];

        foreach ($this->groups->readAll() as $group) {
            if ($group instanceof Group && $group->hasMember($user->getId())) {
                $roles[] = $group->getDisplayName();
            }
        }

        return $roles;
    }

    private function displayName(User $user): string
    {
        foreach ([$user->getDisplayName(), $user->getUserName(), $user->getId()] as $candidate) {
            if ($candidate !== '') {
                return $candidate;
            }
        }

        return $user->getId();
    }
}

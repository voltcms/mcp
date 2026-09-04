<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Contracts;

use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Identity\Identity;

/**
 * Where "who is this?" is answered.
 *
 * An application using voltcms/useraccess does NOT implement this: `UserAccessIdentityProvider`
 * is concrete and takes the `users/` and `groups/` directories. The interface exists for
 * applications whose users live somewhere else.
 *
 * The two methods are separate on purpose, and the separation is a security property rather than
 * a convenience. `currentUser()` answers from the browser session, at the authorize endpoint, and
 * is the only one that can. `findUser()` re-reads the stored record by identifier, with no session
 * in sight, and is what a token validator calls on every request: a token issued an hour ago is
 * only as good as the account behind it is right now, so an account deactivated or demoted after
 * issue must fail here. Collapsing the two into one session-aware lookup would silently turn that
 * guarantee off. See PLAN.md §5.
 */
interface IdentityProviderInterface
{
    /**
     * The authenticated visitor behind this request, or null if there is none.
     *
     * Null is not an error: it is the authorize endpoint's cue to hand the visitor to
     * `LoginRedirectorInterface`.
     */
    public function currentUser(Request $request): ?Identity;

    /**
     * The stored user with this identifier, read fresh, or null if there is no usable account —
     * unknown, deleted, or deactivated. Never consults the session.
     */
    public function findUser(string $identifier): ?Identity;
}

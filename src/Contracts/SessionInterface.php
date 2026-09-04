<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Contracts;

/**
 * "Who is logged in right now?", and nothing else.
 *
 * A consuming application that uses `voltcms/useraccess` does not implement this —
 * `Identity\UserAccessSession` wraps its `SessionAuth`. It exists because the answer has to come
 * from somewhere the package cannot see: PHP sessions, a signed cookie, a framework's security
 * token. Reducing that to one method keeps `UserAccessIdentityProvider` testable, and keeps the
 * package from starting a session of its own alongside the application's.
 *
 * Deliberately NOT part of `IdentityProviderInterface`: the identity provider also answers
 * `findUser()`, which must work with no session in sight — see that interface's docblock.
 */
interface SessionInterface
{
    /**
     * The stored identifier of the authenticated user, or null when nobody is logged in.
     *
     * An identifier, not a username: it is looked up against the store afterwards, and matched
     * exactly.
     */
    public function currentUserIdentifier(): ?string;
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Identity;

use VoltCMS\MCP\Contracts\SessionInterface;
use VoltCMS\UserAccess\GroupProviderInterface;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\UserProviderInterface;

/**
 * `SessionInterface` over `voltcms/useraccess`'s `SessionAuth`.
 *
 * It is a class of its own, and not three lines inside `UserAccessIdentityProvider`, for one
 * reason: `SessionAuth::getInstance()` calls `session_start()`. Constructing it has an effect on
 * the response — a `Set-Cookie` header — which is exactly what the rest of this package promises
 * never to do. Isolating it here means the identity provider stays a pure lookup, and a test can
 * exercise the whole authorize flow without a session ever being started.
 *
 * The session is resolved lazily, on first ask, so an application that never reaches an
 * authenticated endpoint never starts one either.
 */
final class UserAccessSession implements SessionInterface
{
    private ?SessionAuth $session = null;

    public function __construct(
        private readonly UserProviderInterface $users,
        private readonly GroupProviderInterface $groups,
    ) {
    }

    public function currentUserIdentifier(): ?string
    {
        $user = $this->session()->getLoggedInUser();

        return $user === null ? null : $user->getId();
    }

    private function session(): SessionAuth
    {
        return $this->session ??= SessionAuth::getInstance($this->users, $this->groups);
    }
}

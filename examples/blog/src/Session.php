<?php

declare(strict_types=1);

namespace Example\Blog;

use VoltCMS\MCP\Contracts\SessionInterface;

/**
 * "Who is logged in", for an application that keeps its own PHP session rather than using
 * `voltcms/useraccess`'s `SessionAuth`.
 *
 * An application that DOES use `SessionAuth` should pass `Identity\UserAccessSession` instead and
 * delete this file; it is here to show what the seam looks like when the session is the
 * application's own.
 */
final class Session implements SessionInterface
{
    public const KEY = 'blog_user_id';

    public function currentUserIdentifier(): ?string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax']);
        }

        $identifier = $_SESSION[self::KEY] ?? null;

        return is_string($identifier) && $identifier !== '' ? $identifier : null;
    }
}

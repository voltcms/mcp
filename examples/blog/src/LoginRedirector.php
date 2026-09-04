<?php

declare(strict_types=1);

namespace Example\Blog;

use VoltCMS\MCP\Contracts\LoginRedirectorInterface;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;

/**
 * The other interface a consuming application implements, and the one with the trap in it.
 *
 * `$request->uri` is the path AND the query string. Handing back only the path loses the entire
 * authorization request — `client_id`, `redirect_uri`, `state`, `code_challenge` and all — and the
 * client sees the authorize endpoint answer a fresh, parameterless error after a login that
 * appeared to work. That is finding F1 from the first application to integrate this package, and it
 * is why the interface's docblock says so twice.
 *
 * The `next` parameter is validated on the way back out, in login.php: an unvalidated redirect
 * target on a login page is an open redirect, and an open redirect on an authorization server is
 * worth more than usual.
 */
final class LoginRedirector implements LoginRedirectorInterface
{
    public function redirectToLogin(Request $request): Response
    {
        return Response::redirect('/login.php?next=' . rawurlencode($request->uri));
    }
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Contracts;

use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;

/**
 * The other interface a consumer implements, and it is not about security either: the package has
 * no idea where your login page is.
 *
 * You are responsible for preserving the pending request across the round trip. A login flow that
 * redirects back to the current path WITHOUT its query string silently discards the entire
 * authorization request — `client_id`, `redirect_uri`, `state`, `code_challenge` and all — and the
 * client sees an authorize endpoint that answers with a fresh, parameterless error. That is not
 * hypothetical: it is finding F1 in the first consuming application. `Request::$uri` carries the
 * query string precisely so it can be handed back intact.
 */
interface LoginRedirectorInterface
{
    public function redirectToLogin(Request $request): Response;
}

<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\LoginRedirectorInterface;
use VoltCMS\MCP\Http\Request;
use VoltCMS\MCP\Http\Response;

/**
 * Sends the visitor to a login page that echoes back the request target, which is the behaviour
 * finding F1 says a consumer must implement: an authorization request that loses its query string
 * across the login round trip is an authorization request that is gone.
 */
final class RecordingLoginRedirector implements LoginRedirectorInterface
{
    public int $redirectCount = 0;
    public string $lastTarget = '';

    public function redirectToLogin(Request $request): Response
    {
        $this->redirectCount++;
        $this->lastTarget = $request->uri;

        return Response::redirect('/login?next=' . rawurlencode($request->uri));
    }
}

<?php

declare(strict_types=1);

namespace Example\Blog;

use VoltCMS\MCP\Contracts\ConsentViewInterface;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;

/**
 * One of the two interfaces a consuming application implements. It is markup, not security.
 *
 * Three rules, and the package's tests hold it to all three:
 *
 * 1. POST to `$request->formAction`. It already carries the whole authorization request in its
 *    query string, so there is no hidden field to add per parameter.
 * 2. Render `$request->hiddenFields` verbatim. That is the signed ticket binding this approval to
 *    this user, this client and these scopes; a form that drops it never approves anything.
 * 3. Escape everything. `clientName` comes from a document served by whoever the `client_id`
 *    parameter named — the package strips control characters and bounds the length, but the
 *    escaping is yours.
 */
final class ConsentView implements ConsentViewInterface
{
    public function render(ConsentRequest $request): Response
    {
        $scopes = '';

        foreach ($request->scopes as $scope) {
            $scopes .= '<li><code>' . self::escape($scope) . '</code></li>';
        }

        $hidden = '';

        foreach ($request->hiddenFields as $name => $value) {
            $hidden .= '<input type="hidden" name="' . self::escape($name) . '" value="' . self::escape($value) . '">';
        }

        return Response::html(<<<HTML
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Authorise access</title>
                <link rel="stylesheet" href="/assets/site.css">
            </head>
            <body>
                <main class="consent">
                    <h1>Authorise access</h1>

                    <p>
                        <strong>{$this->clientName($request)}</strong> is asking to connect to your
                        site as <strong>{$this->userName($request)}</strong>.
                    </p>

                    <p>It will be able to:</p>
                    <ul>{$scopes}</ul>

                    <p class="muted">It will be sent back to <code>{$this->redirectUri($request)}</code>.</p>

                    <form method="post" action="{$this->formAction($request)}">
                        {$hidden}
                        <button name="consent_decision" value="approve" class="primary">Allow</button>
                        <button name="consent_decision" value="deny">Deny</button>
                    </form>
                </main>
            </body>
            </html>
            HTML);
    }

    private function clientName(ConsentRequest $request): string
    {
        return self::escape($request->clientName);
    }

    private function userName(ConsentRequest $request): string
    {
        return self::escape($request->identity->displayName);
    }

    private function redirectUri(ConsentRequest $request): string
    {
        return self::escape($request->redirectUri);
    }

    private function formAction(ConsentRequest $request): string
    {
        return self::escape($request->formAction);
    }

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}

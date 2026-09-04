<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\Support;

use VoltCMS\MCP\Contracts\ConsentViewInterface;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;

/**
 * Keeps the last ConsentRequest it was handed, so a test can assert on what the user would have
 * been shown — which scopes, which client — rather than on markup nobody in this package writes.
 */
final class RecordingConsentView implements ConsentViewInterface
{
    public ?ConsentRequest $lastRequest = null;
    public int $renderCount             = 0;

    public function render(ConsentRequest $request): Response
    {
        $this->lastRequest = $request;
        $this->renderCount++;

        return Response::html('<form method="post">consent</form>');
    }

    public function ticket(): string
    {
        return $this->lastRequest?->hiddenFields[ConsentRequest::FIELD_TICKET] ?? '';
    }
}

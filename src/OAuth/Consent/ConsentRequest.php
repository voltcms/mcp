<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Consent;

use VoltCMS\MCP\Identity\Identity;

/**
 * Everything a consent screen needs, and nothing it has to work out for itself.
 *
 * The scopes here are the ones that will actually be granted — the request narrowed to what this
 * user's roles support — not the ones the client asked for. Showing the request would be a lie:
 * the user would approve `mcp:write` and receive a token without it.
 *
 * `formAction` already carries the whole authorization request in its query string, so the form
 * needs no hidden field for `client_id`, `redirect_uri`, `state` or the code challenge. The one
 * thing it must echo back is `hiddenFields`, which holds the signed ticket.
 *
 * Immutable.
 */
final class ConsentRequest
{
    // --- The form contract ---

    /** Name of the hidden input carrying the signed ticket. */
    public const FIELD_TICKET = 'consent_ticket';

    /** Name of the submit control carrying the user's answer. */
    public const FIELD_DECISION = 'consent_decision';

    public const DECISION_APPROVE = 'approve';
    public const DECISION_DENY    = 'deny';

    // --- State ---

    public readonly string $clientId;

    /** The client's registered name. Display it escaped: a client can register any name it likes. */
    public readonly string $clientName;

    /** Where the client will be sent back to, already matched against its registration. */
    public readonly string $redirectUri;

    /** @var list<string> The scopes that will be granted if the user approves. */
    public readonly array $scopes;

    public readonly Identity $identity;

    /** Absolute URL the consent form must POST to; carries the authorization request in its query. */
    public readonly string $formAction;

    /** @var array<string, string> Render each as a hidden input, verbatim. */
    public readonly array $hiddenFields;

    /**
     * @param list<string>          $scopes
     * @param array<string, string> $hiddenFields
     */
    public function __construct(
        string $clientId,
        string $clientName,
        string $redirectUri,
        array $scopes,
        Identity $identity,
        string $formAction,
        array $hiddenFields,
    ) {
        $this->clientId     = $clientId;
        $this->clientName   = $clientName === '' ? $clientId : $clientName;
        $this->redirectUri  = $redirectUri;
        $this->scopes       = array_values($scopes);
        $this->identity     = $identity;
        $this->formAction   = $formAction;
        $this->hiddenFields = $hiddenFields;
    }
}

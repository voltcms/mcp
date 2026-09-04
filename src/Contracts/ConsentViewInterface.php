<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Contracts;

use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;

/**
 * One of the two interfaces a consumer implements, and it is not about security.
 *
 * The package decides WHEN to ask for consent and what is being asked; the application decides
 * what that looks like — its markup, its stylesheet, its language. Everything the form must send
 * back is in the `ConsentRequest`: post to its `formAction`, render its `hiddenFields` verbatim,
 * and give the user a submit control named `ConsentRequest::FIELD_DECISION` with the value
 * `DECISION_APPROVE` or `DECISION_DENY`.
 *
 * The hidden fields carry the signed ticket that binds the approval to this user, this client and
 * these scopes. A form that drops them is not a broken style, it is a consent screen whose
 * submissions will never be accepted — which is the failure mode we want, rather than one that
 * accepts a cross-site POST.
 */
interface ConsentViewInterface
{
    public function render(ConsentRequest $request): Response;
}

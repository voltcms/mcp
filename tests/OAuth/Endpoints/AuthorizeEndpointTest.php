<?php

declare(strict_types=1);

namespace VoltCMS\MCP\Tests\OAuth\Endpoints;

use VoltCMS\MCP\Http\PsrAdapter;
use VoltCMS\MCP\Http\Response;
use VoltCMS\MCP\Identity\Identity;
use VoltCMS\MCP\OAuth\Consent\ConsentRequest;
use VoltCMS\MCP\OAuth\Endpoints\AuthorizeEndpoint;
use VoltCMS\MCP\Tests\Support\EndpointTestCase;
use VoltCMS\MCP\Tests\Support\StubIdentityProvider;
use VoltCMS\MCP\Tests\Support\StubScopePolicy;

/**
 * UPGRADE TRIPWIRE — PLAN.md §4.1.
 *
 * The four `testAPlain…` / `testAMissing…` cases below are the reason `AuthorizeEndpoint` exists
 * rather than a bare call into league. league registers a `PlainVerifier` next to the `S256Verifier`
 * and defaults an absent `code_challenge_method` to `plain`; the spike confirmed a `plain`
 * challenge was accepted. If any of them starts passing a challenge through after a dependency
 * upgrade, PKCE has been turned off for this server. Fix the endpoint, do not relax the test.
 *
 * The rest covers the two seams — login and consent — and the binding that stops a consent
 * approval from being forged.
 */
final class AuthorizeEndpointTest extends EndpointTestCase
{
    // --- The S256 tripwire ---

    public function testAPlainCodeChallengeMethodIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['code_challenge_method' => 'plain']));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testAPlainCodeChallengeMethodNeverReachesTheConsentScreen(): void
    {
        $this->getAuthorize($this->authorizeQuery(['code_challenge_method' => 'plain']));

        $this->assertSame(0, $this->consentView->renderCount);
    }

    public function testAnAbsentCodeChallengeMethodIsRefusedRatherThanDefaultedToPlain(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['code_challenge_method' => null]));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testAnUnknownCodeChallengeMethodIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['code_challenge_method' => 'S512']));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testALowercaseS256IsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['code_challenge_method' => 's256']));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    public function testPkceIsRequiredOfAConfidentialClientToo(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery([
            'client_id'             => self::CONFIDENTIAL_ID,
            'code_challenge'        => null,
            'code_challenge_method' => null,
        ]));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
    }

    /**
     * An unknown client AND no code challenge. The answer is the PKCE refusal, not `invalid_client`,
     * which is only true if the guard ran before league saw the request — the ordering CLAUDE.md
     * calls "before delegating".
     */
    public function testTheGuardRunsBeforeLeagueEvenLooksTheClientUp(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery([
            'client_id'             => 'never-registered',
            'code_challenge'        => null,
            'code_challenge_method' => null,
        ]));

        $this->assertSame('invalid_request', $response->decodedBody()['error'] ?? null);
        $this->assertSame(Response::STATUS_BAD_REQUEST, $response->status);
    }

    // --- RFC 8707 ---

    public function testAResourceParameterNamingThisServerIsAccepted(): void
    {
        $this->getAuthorize($this->authorizeQuery(['resource' => 'https://example.com/mcp']));

        $this->assertSame(1, $this->consentView->renderCount);
    }

    public function testAResourceParameterNamingAnotherServerIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['resource' => 'https://attacker.example/mcp']));

        $this->assertSame('invalid_target', $response->decodedBody()['error'] ?? null);
    }

    public function testAResourceParameterDifferingOnlyByATrailingSlashIsAccepted(): void
    {
        $this->getAuthorize($this->authorizeQuery(['resource' => 'https://example.com/mcp/']));

        $this->assertSame(1, $this->consentView->renderCount);
    }

    // --- The login seam ---

    public function testAnUnauthenticatedVisitorIsSentToTheLoginPage(): void
    {
        $this->identities = new StubIdentityProvider(null);
        $this->rebuildAuthorizeEndpoint();

        $response = $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(1, $this->loginRedirector->redirectCount);
        $this->assertSame(Response::STATUS_FOUND, $response->status);
    }

    public function testTheLoginRedirectSeesTheAuthorizationRequestIntact(): void
    {
        $this->identities = new StubIdentityProvider(null);
        $this->rebuildAuthorizeEndpoint();

        $this->getAuthorize($this->authorizeQuery());

        $this->assertStringContainsString('code_challenge=', $this->loginRedirector->lastTarget);
    }

    // --- The consent seam ---

    public function testAGetShowsTheConsentScreenRatherThanIssuingACode(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(Response::STATUS_OK, $response->status);
        $this->assertSame(1, $this->consentView->renderCount);
    }

    public function testTheConsentScreenNamesTheClient(): void
    {
        $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(self::CLIENT_NAME, $this->consentView->lastRequest?->clientName);
    }

    public function testTheConsentScreenShowsTheScopesThatWillActuallyBeGranted(): void
    {
        $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(['mcp:read', 'mcp:write'], $this->consentView->lastRequest?->scopes);
    }

    public function testTheConsentFormPostsBackToTheConfiguredAuthorizeUrl(): void
    {
        $this->getAuthorize($this->authorizeQuery());

        $this->assertStringStartsWith(
            'https://example.com/oauth/authorize?',
            (string) $this->consentView->lastRequest?->formAction,
        );
    }

    public function testApprovingIssuesAnAuthorizationCode(): void
    {
        $query = $this->authorizeQuery();
        $this->getAuthorize($query);

        $response = $this->postConsent($query, $this->consentView->ticket());

        $this->assertSame(Response::STATUS_FOUND, $response->status);
        $this->assertStringStartsWith(self::REDIRECT_URI . '?', (string) $response->header('Location'));
    }

    public function testTheRedirectCarriesTheStateItWasGiven(): void
    {
        $query = $this->authorizeQuery();
        $this->getAuthorize($query);

        $location = (string) $this->postConsent($query, $this->consentView->ticket())->header('Location');
        parse_str((string) parse_url($location, PHP_URL_QUERY), $parameters);

        $this->assertSame('xyz', $parameters['state'] ?? null);
    }

    public function testDenyingRedirectsBackWithAccessDenied(): void
    {
        $query = $this->authorizeQuery();
        $this->getAuthorize($query);

        $response = $this->postConsent($query, $this->consentView->ticket(), ConsentRequest::DECISION_DENY);
        parse_str((string) parse_url((string) $response->header('Location'), PHP_URL_QUERY), $parameters);

        $this->assertSame('access_denied', $parameters['error'] ?? null);
    }

    // --- Binding the approval ---

    public function testAPostWithNoTicketShowsTheConsentScreenAgainRatherThanApproving(): void
    {
        $query = $this->authorizeQuery();

        $response = $this->postConsent($query, '');

        $this->assertSame(Response::STATUS_OK, $response->status);
        $this->assertSame(1, $this->consentView->renderCount);
    }

    public function testATicketIssuedForAnotherClientDoesNotApproveThisOne(): void
    {
        $issued = $this->authorizeQuery();
        $this->getAuthorize($issued);
        $ticket = $this->consentView->ticket();

        $response = $this->postConsent($this->authorizeQuery(['client_id' => self::CONFIDENTIAL_ID]), $ticket);

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    public function testATicketIssuedForAnotherUserDoesNotApproveThisRequest(): void
    {
        $query = $this->authorizeQuery();
        $this->getAuthorize($query);
        $ticket = $this->consentView->ticket();

        $this->identities = new StubIdentityProvider(new Identity('someone-else', 'Someone Else', ['editor']));
        $this->rebuildAuthorizeEndpoint();

        $response = $this->postConsent($query, $ticket);

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    public function testATamperedTicketDoesNotApprove(): void
    {
        $query = $this->authorizeQuery();
        $this->getAuthorize($query);

        $ticket = $this->consentView->ticket();
        $forged = substr($ticket, 0, -1) . (str_ends_with($ticket, 'a') ? 'b' : 'a');

        $response = $this->postConsent($query, $forged);

        $this->assertSame(Response::STATUS_OK, $response->status);
    }

    // --- Scopes ---

    public function testAScopeTheUsersRolesDoNotSupportIsDroppedFromTheGrant(): void
    {
        $this->rebuildAuthorizeEndpoint(['mcp:read']);

        $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(['mcp:read'], $this->consentView->lastRequest?->scopes);
    }

    public function testAUserWhoCanGrantNothingIsRefused(): void
    {
        $this->rebuildAuthorizeEndpoint([]);

        $response = $this->getAuthorize($this->authorizeQuery());

        $this->assertSame(Response::STATUS_FOUND, $response->status);
        $this->assertStringContainsString('error=invalid_scope', (string) $response->header('Location'));
    }

    public function testAClientAskingForNoScopeIsOfferedEverythingItCouldHave(): void
    {
        $this->getAuthorize($this->authorizeQuery(['scope' => null]));

        $this->assertSame(['mcp:read', 'mcp:write'], $this->consentView->lastRequest?->scopes);
    }

    public function testAScopeThisServerDoesNotConfigureIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['scope' => 'mcp:admin']));

        $this->assertStringContainsString('error=invalid_scope', (string) $response->header('Location'));
    }

    // --- Method and client guards ---

    public function testAnUnknownClientIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['client_id' => 'never-registered']));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testAWildcardClientIdMatchesNoRegisteredClient(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['client_id' => 'claude*']));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testAForeignRedirectUriIsRefused(): void
    {
        $response = $this->getAuthorize($this->authorizeQuery(['redirect_uri' => 'https://attacker.example/callback']));

        $this->assertSame(Response::STATUS_UNAUTHORIZED, $response->status);
    }

    public function testNothingIsWrittenToTheOutputBuffer(): void
    {
        ob_start();
        $this->getAuthorize($this->authorizeQuery());
        $emitted = (string) ob_get_clean();

        $this->assertSame('', $emitted);
    }

    // --- Helpers ---

    /**
     * @param list<string>|null $grantable
     */
    private function rebuildAuthorizeEndpoint(?array $grantable = null): void
    {
        $this->authorize = new AuthorizeEndpoint(
            $this->server,
            $this->configuration,
            $this->identities,
            new StubScopePolicy($grantable ?? ['mcp:read', 'mcp:write']),
            $this->consentView,
            $this->loginRedirector,
            $this->tickets,
            new PsrAdapter(),
        );
    }
}

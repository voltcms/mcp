<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

/**
 * The default fetcher: `SsrfGuard`, then an HTTPS GET with everything turned off.
 *
 * Deliberately built on PHP's stream wrapper rather than a PSR-18 client. A PSR-18 implementation
 * is not a dependency of this package and cannot be — the whole premise is shared hosting with
 * whatever is already installed — and `allow_url_fopen` with `https` is the one HTTP client a
 * host of that kind reliably has. When `ext-curl` IS present it is used instead, for one specific
 * reason given below.
 *
 * What is turned off, and why each one:
 *
 * - **Redirects, entirely.** PLAN.md §5 asks for no cross-host redirects; refusing all of them is
 *   simpler to be sure of, and a metadata document that needs a redirect to be found is a
 *   metadata document at the wrong URL.
 * - **Anything but HTTPS on port 443**, and any address that is not globally routable. That is
 *   `SsrfGuard`, and its docblock explains what it is defending.
 * - **Size**, capped while reading rather than after: a caller cannot make this server buffer a
 *   gigabyte by pointing it at one.
 * - **Time**, capped well under the ~30 s a shared host allows a request, so a slow server cannot
 *   hold this one open until it is killed.
 *
 * ## Why curl, when it is there
 *
 * `SsrfGuard` resolves the host and approves an address, but the stream wrapper then resolves the
 * host again when it connects — and DNS is free to answer differently the second time. That race
 * is the whole of DNS rebinding. curl closes it: `CURLOPT_RESOLVE` pins the connection to the
 * address that was approved, so the name is resolved once. Without ext-curl the race remains, and
 * saying so here is better than implying it does not.
 */
final class StreamClientIdMetadataFetcher implements ClientIdMetadataFetcherInterface
{
    public const EXCEPTION_FETCH_FAILED  = 10201;
    public const EXCEPTION_TOO_LARGE     = 10202;

    /** A metadata document is a few hundred bytes. Anything approaching this is not one. */
    public const MAXIMUM_BYTES = 65536;

    public const TIMEOUT_SECONDS = 5;

    private const ACCEPT     = 'application/json';
    private const USER_AGENT = 'voltcms-mcp';

    private readonly SsrfGuard $guard;

    public function __construct(?SsrfGuard $guard = null)
    {
        $this->guard = $guard ?? new SsrfGuard();
    }

    public function fetch(string $url): string
    {
        $address = $this->guard->guard($url);

        $body = function_exists('curl_init')
            ? $this->fetchWithCurl($url, $address)
            : $this->fetchWithStream($url);

        if (strlen($body) > self::MAXIMUM_BYTES) {
            throw new \RuntimeException('The client metadata document is too large.', self::EXCEPTION_TOO_LARGE);
        }

        return $body;
    }

    /**
     * @param string $address The address `SsrfGuard` approved, pinned so the name is resolved once.
     */
    private function fetchWithCurl(string $url, string $address): string
    {
        $host   = (string) parse_url($url, PHP_URL_HOST);
        $handle = curl_init($url);

        if ($handle === false) {
            throw new \RuntimeException('Unable to fetch the client metadata document.', self::EXCEPTION_FETCH_FAILED);
        }

        // CURLOPT_PROTOCOLS_STR needs libcurl 7.85; without it FOLLOWLOCATION being off already
        // means no protocol but the requested one is ever reached.
        $protocols = defined('CURLOPT_PROTOCOLS_STR') ? [CURLOPT_PROTOCOLS_STR => 'https'] : [];

        curl_setopt_array($handle, $protocols + [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => self::TIMEOUT_SECONDS,
            CURLOPT_TIMEOUT        => self::TIMEOUT_SECONDS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT      => self::USER_AGENT,
            CURLOPT_HTTPHEADER     => ['Accept: ' . self::ACCEPT],
            CURLOPT_RESOLVE        => [$host . ':443:' . $address],
            CURLOPT_BUFFERSIZE     => 8192,
            CURLOPT_NOPROGRESS     => false,
            CURLOPT_PROGRESSFUNCTION => static fn (mixed $handle, int $expected, int $received): int
                => $received > self::MAXIMUM_BYTES || $expected > self::MAXIMUM_BYTES ? 1 : 0,
        ]);

        $body   = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);

        curl_close($handle);

        if (!is_string($body) || $status !== 200) {
            throw new \RuntimeException('Unable to fetch the client metadata document.', self::EXCEPTION_FETCH_FAILED);
        }

        return $body;
    }

    private function fetchWithStream(string $url): string
    {
        $context = stream_context_create(['http' => [
            'method'           => 'GET',
            'follow_location'  => 0,
            'max_redirects'    => 0,
            'timeout'          => self::TIMEOUT_SECONDS,
            'ignore_errors'    => false,
            'header'           => "Accept: " . self::ACCEPT . "\r\nUser-Agent: " . self::USER_AGENT . "\r\n",
        ]]);

        $stream = @fopen($url, 'rb', false, $context);

        if ($stream === false) {
            throw new \RuntimeException('Unable to fetch the client metadata document.', self::EXCEPTION_FETCH_FAILED);
        }

        // One byte over the cap, so a document exactly at the limit is accepted and one above it is
        // detected without ever reading the rest.
        $body = (string) stream_get_contents($stream, self::MAXIMUM_BYTES + 1);

        fclose($stream);

        return $body;
    }
}

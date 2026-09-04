<?php

declare(strict_types=1);

namespace VoltCMS\MCP\OAuth\Clients;

/**
 * Decides whether a URL this server has been ASKED to fetch is one it should fetch.
 *
 * A Client ID Metadata Document is a URL an unauthenticated caller puts in a `client_id`
 * parameter, and fetching it turns the authorization server into an HTTP client aimed wherever
 * that caller likes. On a shared host that is a request originating inside the network perimeter:
 * `http://169.254.169.254/latest/meta-data/` on a cloud instance, `http://127.0.0.1:6379/` at a
 * Redis that speaks enough HTTP to be confused, a neighbour's admin panel on `10.0.0.0/8`.
 *
 * The guard therefore resolves the host itself and inspects the address, rather than trusting the
 * hostname: `metadata.attacker.example` resolving to `169.254.169.254` is the whole attack, and no
 * amount of hostname filtering catches it.
 *
 * ## The limit, stated rather than hidden
 *
 * Between this check and the connection the fetcher makes, DNS can change its answer — the classic
 * rebinding race. `guard()` therefore RETURNS the address it approved so a caller able to pin the
 * connection to it can; `StreamClientIdMetadataFetcher` pins it when `ext-curl` is available and
 * says so in its docblock when it is not.
 *
 * The DNS resolver is injectable because a guard that could only be exercised against real DNS
 * could not be exercised in this suite at all — PLAN.md §6: no network, ever.
 */
final class SsrfGuard
{
    // --- Failure codes ---

    public const EXCEPTION_URL_MALFORMED   = 10001;
    public const EXCEPTION_SCHEME_INSECURE = 10002;
    public const EXCEPTION_PORT_REFUSED    = 10003;
    public const EXCEPTION_HOST_UNRESOLVED = 10004;
    public const EXCEPTION_ADDRESS_PRIVATE = 10005;

    /**
     * Only the default HTTPS port. A metadata document on `:8443` is a document on a service this
     * server has no way to reason about, and the ports worth reaching internally are all unusual.
     */
    public const ALLOWED_PORTS = [443];

    /** @var \Closure(string): list<string> */
    private readonly \Closure $resolver;

    /**
     * @param (callable(string): list<string>)|null $resolver Host name to IP addresses. Defaults to DNS.
     */
    public function __construct(?callable $resolver = null)
    {
        $this->resolver = $resolver === null
            ? static fn (string $host): array => self::resolve($host)
            : \Closure::fromCallable($resolver);
    }

    /**
     * @return string The approved IP address, for a caller that can pin the connection to it.
     *
     * @throws \InvalidArgumentException with one of the EXCEPTION_* codes above.
     */
    public function guard(string $url): string
    {
        $parts = parse_url(trim($url));

        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            throw new \InvalidArgumentException(
                'A client metadata URL must be absolute.',
                self::EXCEPTION_URL_MALFORMED,
            );
        }

        if (strtolower($parts['scheme']) !== 'https') {
            throw new \InvalidArgumentException(
                'A client metadata URL must use https.',
                self::EXCEPTION_SCHEME_INSECURE,
            );
        }

        if (isset($parts['port']) && !in_array($parts['port'], self::ALLOWED_PORTS, true)) {
            throw new \InvalidArgumentException(
                'A client metadata URL must be served on the default https port.',
                self::EXCEPTION_PORT_REFUSED,
            );
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new \InvalidArgumentException(
                'A client metadata URL must not carry credentials or a fragment.',
                self::EXCEPTION_URL_MALFORMED,
            );
        }

        return $this->approvedAddress(trim($parts['host'], '[]'));
    }

    /**
     * Every address the host resolves to has to be routable. Checking only the first would let a
     * round-robin record put a private address in second place and be fetched on the retry.
     */
    private function approvedAddress(string $host): string
    {
        $addresses = ($this->resolver)($host);

        if ($addresses === []) {
            throw new \InvalidArgumentException(
                'The client metadata host does not resolve.',
                self::EXCEPTION_HOST_UNRESOLVED,
            );
        }

        foreach ($addresses as $address) {
            if (!self::isPublic($address)) {
                throw new \InvalidArgumentException(
                    'The client metadata host resolves to an address this server will not fetch.',
                    self::EXCEPTION_ADDRESS_PRIVATE,
                );
            }
        }

        return $addresses[0];
    }

    /**
     * Public means globally routable. `FILTER_FLAG_NO_PRIV_RANGE` and `NO_RES_RANGE` between them
     * cover RFC 1918, loopback, link-local (169.254/16 and fe80::/10, which is where cloud metadata
     * services live), the IPv6 unique-local block and the reserved ranges — and a string that is
     * not an IP address at all fails the filter outright, which is the answer we want for it too.
     */
    private static function isPublic(string $address): bool
    {
        return filter_var(
            $address,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }

    /**
     * @return list<string>
     */
    private static function resolve(string $host): array
    {
        $addresses = [];

        foreach (['A' => DNS_A, 'AAAA' => DNS_AAAA] as $field => $type) {
            foreach (@dns_get_record($host, $type) ?: [] as $record) {
                $value = $record[$field === 'A' ? 'ip' : 'ipv6'] ?? null;

                if (is_string($value) && $value !== '') {
                    $addresses[] = $value;
                }
            }
        }

        return $addresses;
    }
}

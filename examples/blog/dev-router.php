<?php

declare(strict_types=1);

/**
 * Router for PHP's built-in server, so the example can be run locally the way its README says.
 *
 *     php -S localhost:8080 -t examples/blog/public examples/blog/dev-router.php
 *
 * It exists because the built-in server has no rewrite rules, and the two obvious things to try
 * both fail:
 *
 * - `php -S … -t public` alone never routes `/.well-known/…` or `/oauth/…` to PHP at all, because
 *   no file sits at those paths. Discovery 404s and every client gives up at the first hop.
 * - `php -S … public/mcp.php` sends *everything* through the front controller, including
 *   `/login.php` and `/assets/site.css`, which the front controller does not know about — so the
 *   login page 404s and the consent screen loads unstyled.
 *
 * The rule below is the one Apache and nginx express as rewrites: a request that maps to a real
 * file is served as that file, and everything else goes to the front controller. Only for local
 * development — in production the web server does this, and the snippets are in the root README.
 */

$path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$file = __DIR__ . '/public' . $path;

if ($path !== '/' && is_file($file)) {
    return false;
}

require __DIR__ . '/public/mcp.php';

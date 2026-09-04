<?php

declare(strict_types=1);

/**
 * The application's own login page — not part of `voltcms/mcp`, and shown here only because the
 * authorization endpoint hands unauthenticated visitors to it and expects them back.
 *
 * The one thing this file has to get right is `next`. It arrives from `LoginRedirector` carrying
 * the whole authorization request, and it has to survive the round trip intact — dropping the query
 * string is finding F1, and the client sees a parameterless error after a login that seemed to
 * work. It also has to be validated before it is used as a redirect target: an open redirect on the
 * login page of an authorization server is worth more than an open redirect usually is.
 */

namespace Example\Blog;

use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\LoginThrottle;
use VoltCMS\UserAccess\SessionAuth;
use VoltCMS\UserAccess\UserProvider;

require dirname(__DIR__) . '/bootstrap.php';

session_start(['cookie_httponly' => true, 'cookie_samesite' => 'Lax']);

/** A path on this site, and nothing else. `//evil.example` and `https://evil.example` are not paths. */
$next = (string) ($_GET['next'] ?? '/');

if ($next === '' || $next[0] !== '/' || str_starts_with($next, '//')) {
    $next = '/';
}

$error = '';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $session = SessionAuth::getInstance(
        UserProvider::getInstance(),
        GroupProvider::getInstance(),
    );

    if ($session->login((string) ($_POST['username'] ?? ''), (string) ($_POST['password'] ?? ''))) {
        $_SESSION[Session::KEY] = $session->getLoggedInUser()?->getId();

        header('Location: ' . $next, true, 302);

        exit;
    }

    $error = 'Those credentials were not accepted.';
}

$escapedNext  = htmlspecialchars($next, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$escapedError = htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
    <main class="login">
        <h1>Sign in</h1>

        <?php if ($escapedError !== ''): ?><p class="error"><?= $escapedError ?></p><?php endif; ?>

        <form method="post" action="/login.php?next=<?= rawurlencode($next) ?>">
            <label>Username <input name="username" autocomplete="username" required></label>
            <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
            <button class="primary">Sign in</button>
        </form>
    </main>
</body>
</html>

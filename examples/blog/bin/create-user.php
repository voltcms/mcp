<?php

declare(strict_types=1);

/**
 * Creates a user and puts them in groups, because `voltcms/useraccess` ships no CLI of its own and
 * a server nobody can log in to cannot be authorized against.
 *
 *     php bin/create-user.php jannis 'a-real-passphrase' editors
 *
 * Group display names are what `ScopePolicy` matches on, so `editors` here is the same `editors`
 * that bootstrap.php maps to `mcp:write`. A user in no group still gets whatever the policy grants
 * `forEveryone`.
 *
 * Passwords are hashed by useraccess on the way in and must be at least
 * `User::PASSWORD_MIN_LENGTH` characters. Nothing here echoes the password back.
 */

namespace Example\Blog;

use VoltCMS\UserAccess\Group;
use VoltCMS\UserAccess\GroupProvider;
use VoltCMS\UserAccess\User;
use VoltCMS\UserAccess\UserProvider;

require dirname(__DIR__) . '/bootstrap.php';

$userName = $argv[1] ?? '';
$password = $argv[2] ?? '';
$groups   = array_slice($argv, 3);

if ($userName === '' || $password === '') {
    fwrite(STDERR, "Usage: create-user.php <username> <password> [group ...]\n");

    exit(1);
}

$users      = UserProvider::getInstance();
$groupStore = GroupProvider::getInstance();

if ($users->exists('userName', $userName)) {
    fwrite(STDERR, 'A user named ' . $userName . " already exists.\n");

    exit(1);
}

$user = new User();
$user->setUserName($userName);
$user->setDisplayName($userName);
$user->setPassword($password);
$user->setActive(true);

$created = $users->create($user);

echo 'Created user ', $userName, "\n";
echo '  id: ', $created->getId(), "\n";

foreach ($groups as $groupName) {
    if ($groupStore->exists('displayName', $groupName)) {
        $group = $groupStore->read('displayName', $groupName);
    } else {
        $group = new Group();
        $group->setDisplayName($groupName);
        $group = $groupStore->create($group);
    }

    $group->addMember($created->getId());
    $groupStore->update($group);

    echo '  added to group: ', $groupName, "\n";
}

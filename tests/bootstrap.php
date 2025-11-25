<?php

declare(strict_types=1);

$projectRoot = dirname(__DIR__);
require_once($projectRoot . '/vendor/autoload.php');

// Load our wrapper class to get around login() being declared protected in SQL.php
require_once($projectRoot . '/tests/src/Auth/Source/SQLWrapper.php');
require_once($projectRoot . '/tests/src/Auth/Source/PasswordVerifyWrapper.php');

// Symlink module into ssp vendor lib so that templates and urls can resolve correctly
$linkPath = $projectRoot . '/vendor/simplesamlphp/simplesamlphp/modules/sqlauth';
if (file_exists($linkPath) === false) {
    echo "Linking '$linkPath' to '$projectRoot'\n";
    symlink($projectRoot, $linkPath);
}

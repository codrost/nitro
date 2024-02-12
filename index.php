<?php
require 'vendor/autoload.php';

$f3 = \Base::instance();

// Load configuration file
$f3->set('ENVIRONMENT', 'live');
if (strstr($f3->get('HOST'), 'local') !== false || strstr($f3->get('HOST'), '127.0.0.1') !== false) {
    $f3->set('ENVIRONMENT', 'development');
} elseif (strstr($f3->get('HOST'), 'acceptatie') !== false || strstr($f3->get('HOST'), '91.238.177.17') !== false) {
    $f3->set('ENVIRONMENT', 'acceptance');
}

$f3->config('app/config/' . $f3->get('ENVIRONMENT') . '.ini');

if (!$f3->exists('SESSION.NITROCSRF')) {
    $f3->set('SESSION.NITROCSRF', bin2hex(random_bytes(32)));
}

$f3->config('app/config/variables.ini');

# Set the needed file directories for the application
foreach ($f3->get('storage.subdirectories') as $directory) {
    $fullPath = $f3->get('storage.directory') . '/' . $f3->get('ENVIRONMENT') . '/' . $directory;
    if (!is_dir($fullPath)) mkdir($fullPath, 0776, true);
    $f3->set(strtoupper($directory), $f3->get('storage.directory') . '/' . $f3->get('ENVIRONMENT') . '/' . $directory);
}

$f3->config('app/config/routes.ini');
$f3->config('app/config/redirects.ini');

$f3->run();

<?php

declare(strict_types=1);

/**
 * MIME Shield - PHPStan bootstrap.
 *
 * Defines the global constants that Roundcube defines at runtime (iniset.php / bootstrap.php /
 * clisetup.php) so PHPStan can resolve them. Roundcube classes themselves are discovered through
 * scanDirectories in phpstan.neon.dist. Nothing here is executed in production.
 *
 * The Roundcube installation used for analysis is taken from the environment variable MIMESHIELD_RC
 * (default /opt/rcrun/1.7.4); see phpstan.neon.dist.
 *
 * @license GPL-3.0-or-later
 */

$rc = getenv('MIMESHIELD_RC');
$rc = is_string($rc) && $rc !== '' ? rtrim($rc, '/') . '/' : '/opt/rcrun/1.7.4/';

foreach ([
    'INSTALL_PATH' => $rc,
    'RCUBE_INSTALL_PATH' => $rc,
    'RCUBE_CONFIG_DIR' => $rc . 'config/',
    'RCUBE_PLUGINS_DIR' => $rc . 'plugins/',
    'RCUBE_LOCALIZATION_DIR' => $rc . 'program/localization/',
    'RCMAIL_VERSION' => '1.7.4',
    'RCUBE_VERSION' => '1.7.4',
    'RCUBE_CHARSET' => 'UTF-8',
    'JS_OBJECT_NAME' => 'rcmail',
] as $name => $value) {
    if (!defined($name)) {
        define($name, $value);
    }
}

// Do NOT require lib/autoload.php here: plugin classes extend Roundcube/PEAR classes (Mail_mime ...)
// that are only known statically; PHPStan discovers the analysed files itself.

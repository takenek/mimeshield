<?php

declare(strict_types=1);

/**
 * MIME Shield - PHPUnit bootstrap.
 *
 * Unit tests need only lib/. Integration tests additionally load Roundcube's library (Mail_mime,
 * rcube_mime, rcube_message_part ...) from the Roundcube installation given in the environment
 * variable MIMESHIELD_RC (e.g. MIMESHIELD_RC=/var/www/roundcube).
 *
 * @license GPL-3.0-or-later
 */

error_reporting(E_ALL);
ini_set('display_errors', '1');

require_once __DIR__ . '/../lib/autoload.php';
require_once __DIR__ . '/TestPki.php';

$rc = getenv('MIMESHIELD_RC');
if (is_string($rc) && $rc !== '' && is_file($rc . '/program/lib/Roundcube/bootstrap.php')) {
    define('MIMESHIELD_RC_LOADED', true);
    if (!defined('RCUBE_INSTALL_PATH')) {
        define('RCUBE_INSTALL_PATH', rtrim($rc, '/') . '/');
    }
    if (!defined('RCUBE_CONFIG_DIR')) {
        define('RCUBE_CONFIG_DIR', RCUBE_INSTALL_PATH . 'config/');
    }
    if (!defined('RCUBE_PLUGINS_DIR')) {
        define('RCUBE_PLUGINS_DIR', RCUBE_INSTALL_PATH . 'plugins/');
    }
    if (!defined('RCUBE_LOCALIZATION_DIR')) {
        define('RCUBE_LOCALIZATION_DIR', RCUBE_INSTALL_PATH . 'program/localization/');
    }
    require_once RCUBE_INSTALL_PATH . 'vendor/autoload.php';
    require_once RCUBE_INSTALL_PATH . 'program/lib/Roundcube/bootstrap.php';
} else {
    define('MIMESHIELD_RC_LOADED', false);
}

// keep test logs out of the Roundcube log
MimeShield\Log::setSink(static function (string $line): void {
    $GLOBALS['mimeshield_test_log'][] = $line;
});

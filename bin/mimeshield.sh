#!/usr/bin/env php
<?php

/**
 * MIME Shield - administration tool (diagnostics, master key generation and rotation).
 *
 * Run from the Roundcube installation directory as the user owning the Roundcube files, e.g.:
 *   plugins/mimeshield/bin/mimeshield.sh diag
 *
 * @license GPL-3.0-or-later
 */

// Roundcube root: $ROUNDCUBE_INSTALL_PATH, or <root>/plugins/mimeshield/bin as invoked (a symlinked
// plugin directory is resolved by __DIR__, so the invocation path is tried first)
$candidates = [];
if (is_string(getenv('ROUNDCUBE_INSTALL_PATH')) && getenv('ROUNDCUBE_INSTALL_PATH') !== '') {
    $candidates[] = rtrim((string) getenv('ROUNDCUBE_INSTALL_PATH'), '/');
}
$invoked = (string) ($_SERVER['SCRIPT_FILENAME'] ?? '');
if ($invoked !== '') {
    if ($invoked[0] !== '/') {
        $invoked = getcwd() . '/' . $invoked;
    }
    $candidates[] = dirname($invoked, 4);
}
$candidates[] = dirname(__DIR__, 3);
$root = null;
foreach ($candidates as $c) {
    if (is_file($c . '/program/include/clisetup.php')) {
        $root = $c;
        break;
    }
}
if ($root === null) {
    fwrite(STDERR, "Roundcube not found: install the plugin as <roundcube>/plugins/mimeshield or set ROUNDCUBE_INSTALL_PATH\n");
    exit(1);
}
define('INSTALL_PATH', $root . '/');

require_once INSTALL_PATH . 'program/include/clisetup.php';
require_once __DIR__ . '/../lib/autoload.php';

$rcmail = rcube::get_instance();
$args = rcube_utils::get_opt(['f' => 'file', 'k' => 'kid', 'a' => 'append:bool', 'n' => 'dry-run:bool']);

$tool = new MimeShield\Cli\Tool($rcmail, realpath(__DIR__ . '/..'));
exit($tool->run($args));

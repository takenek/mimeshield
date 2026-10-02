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

define('INSTALL_PATH', realpath(__DIR__ . '/../../../') . '/');

if (!is_file(INSTALL_PATH . 'program/include/clisetup.php')) {
    fwrite(STDERR, "Roundcube not found: the plugin must be installed as <roundcube>/plugins/mimeshield\n");
    exit(1);
}

require_once INSTALL_PATH . 'program/include/clisetup.php';
require_once __DIR__ . '/../lib/autoload.php';

$rcmail = rcube::get_instance();
$args = rcube_utils::get_opt(['f' => 'file', 'k' => 'kid', 'a' => 'append:bool', 'n' => 'dry-run:bool']);

$tool = new MimeShield\Cli\Tool($rcmail, realpath(__DIR__ . '/..'));
exit($tool->run($args));

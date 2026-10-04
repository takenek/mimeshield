<?php

declare(strict_types=1);

/**
 * Copyright (C) 2026 TaKeN.PL Usługi Informatyczne Marek Królikowski
 * Original author: Marek Królikowski (TaKeN)
 * Original project: https://github.com/takenek/mimeshield
 * SPDX-License-Identifier: GPL-3.0-or-later
 * See LICENSE and COPYRIGHT for the license and GPL section 7 attribution terms.
 *
 * MIME Shield - S/MIME for Roundcube
 *
 * PSR-4 autoloader for the MimeShield\ namespace (lib/MimeShield). Used when the plugin is installed
 * without Composer (git clone / tarball); Composer installs use the autoload section of composer.json.
 *
 * @license GPL-3.0-or-later
 */

spl_autoload_register(static function (string $class): void {
    if (strncmp($class, 'MimeShield\\', 11) !== 0) {
        return;
    }
    $rel = str_replace('\\', '/', substr($class, 11));
    if (!preg_match('~^[A-Za-z0-9_/]+$~', $rel)) {
        return;
    }
    $file = __DIR__ . '/MimeShield/' . $rel . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

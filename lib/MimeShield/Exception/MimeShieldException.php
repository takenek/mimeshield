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
 * @license GPL-3.0-or-later
 */

namespace MimeShield\Exception;

/**
 * Base exception of the plugin.
 *
 * Every exception carries two independent messages:
 *  - a localization label (without the "mimeshield." prefix) that is safe to show to the end user,
 *  - an internal message for the administrator log (never shown to the user).
 */
class MimeShieldException extends \RuntimeException
{
    /** @var array<string, string> */
    private array $vars;

    private string $userLabel;

    /**
     * @param string                $userLabel Localization label (plugin domain) shown to the user
     * @param string                $internal  Detailed message for the log (must not contain secrets)
     * @param array<string, string> $vars      Variables substituted into the label (escaped by Roundcube)
     */
    public function __construct(string $userLabel, string $internal = '', array $vars = [], ?\Throwable $previous = null)
    {
        parent::__construct($internal !== '' ? $internal : $userLabel, 0, $previous);
        $this->userLabel = $userLabel;
        $this->vars = $vars;
    }

    public function getUserLabel(): string
    {
        return $this->userLabel;
    }

    /**
     * @return array<string, string>
     */
    public function getVars(): array
    {
        return $this->vars;
    }
}

<?php

declare(strict_types=1);

/**
 * MIME Shield - PHP CS Fixer configuration.
 *
 * PSR-12 based, aligned with Roundcube 1.7's own style where it matters (one space around the
 * concatenation operator, no Yoda conditions, short arrays, single quotes), and deliberately WITHOUT
 * risky rules: the fixer must never change behaviour of crypto / parsing code.
 *
 * Check only (CI):   vendor/bin/php-cs-fixer fix --dry-run --diff
 *
 * @license GPL-3.0-or-later
 */

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = Finder::create()
    ->in(__DIR__)
    ->exclude([
        'vendor',
        'tmp',
        'build',
        'node_modules',
        'tests/fixtures',
        'tests/e2e',
    ])
    ->ignoreDotFiles(false)
    ->name('*.php')
    ->name('*.php.dist')
    ->name('*.inc')
    ->append([__DIR__ . '/bin/mimeshield.sh']);

return (new Config())
    ->setRiskyAllowed(false)
    ->setRules([
        '@PSR12' => true,

        // Roundcube style (see roundcubemail/.php-cs-fixer.dist.php)
        'concat_space' => ['spacing' => 'one'],
        'yoda_style' => false,
        'array_syntax' => ['syntax' => 'short'],
        'single_quote' => true,
        'increment_style' => ['style' => 'post'],
        'method_argument_space' => ['on_multiline' => 'ignore'],

        // safe hygiene
        'no_unused_imports' => true,
        'ordered_imports' => ['sort_algorithm' => 'alpha', 'imports_order' => ['class', 'function', 'const']],
        'no_whitespace_in_blank_line' => true,
        'no_trailing_whitespace_in_comment' => true,
        'no_extra_blank_lines' => true,
        'trailing_comma_in_multiline' => ['elements' => ['arrays']],
        'binary_operator_spaces' => ['default' => 'single_space'],
        'cast_spaces' => ['space' => 'single'],
        'no_empty_statement' => true,
        'no_singleline_whitespace_before_semicolons' => true,
        'standardize_not_equals' => true,
        'lowercase_cast' => true,
        'native_type_declaration_casing' => true,
        'nullable_type_declaration_for_default_null_value' => true, // PHP 8.4: implicit nullable is deprecated
        'phpdoc_indent' => true,
        'phpdoc_trim' => true,
        'phpdoc_scalar' => true,
        'phpdoc_single_line_var_spacing' => true,
    ])
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/tmp/.php-cs-fixer.cache');

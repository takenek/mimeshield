<?php

declare(strict_types=1);

namespace MimeShield\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * The Packagist and License badges of the README are files of this repository: GitHub's image
 * proxy (camo) gave up on img.shields.io after about four seconds ("504 Error Fetching Resource")
 * whenever it had no cached copy, and both badges then showed as broken images on github.com and
 * packagist.org (which renders the README through GitHub). raw.githubusercontent.com is not
 * proxied. packagist.org shows those images through rawcdn.githack.com, which caches a URL for a
 * year (immutable): the version badge therefore carries the version in its file name - every
 * release adds a new file and keeps the old ones, which the READMEs of earlier releases link
 * (docs/RELEASING.md step 2). The licence never changes.
 *
 * @license GPL-3.0-or-later
 */
final class ReadmeBadgesTest extends TestCase
{
    private static function root(): string
    {
        return dirname(__DIR__, 2);
    }

    private static function read(string $file): string
    {
        return (string) file_get_contents(self::root() . '/' . $file);
    }

    public function testTheReadmeBadgesAreRepositoryFilesThatNameTheCurrentRelease(): void
    {
        self::assertSame(1, preg_match("/'version' => '(\\d+\\.\\d+\\.\\d+)'/", self::read('mimeshield.php'), $m));
        $version = $m[1];
        $license = json_decode(self::read('composer.json'), true, 512, JSON_THROW_ON_ERROR)['license'];
        self::assertIsString($license);
        $readme = self::read('README.md');
        $raw = 'https://raw.githubusercontent.com/takenek/mimeshield/main/.github/badges/';
        self::assertStringContainsString("[![Packagist]({$raw}packagist-v{$version}.svg)](https://packagist.org/packages/takenek/mimeshield)", $readme);
        self::assertStringContainsString("[![License]({$raw}license.svg)](LICENSE)", $readme);
        self::assertStringNotContainsString('img.shields.io', $readme, 'GitHub\'s image proxy does not reliably fetch shields.io');

        $files = array_values(array_diff((array) scandir(self::root() . '/.github/badges'), ['.', '..']));
        self::assertContains('license.svg', $files);
        self::assertContains("packagist-v{$version}.svg", $files, 'the version badge of this release');
        // the badges of earlier releases stay (their READMEs link them through main), each naming its own version
        foreach ($files as $file) {
            if ($file === 'license.svg') {
                continue;
            }
            self::assertSame(1, preg_match('/^packagist-v(\d+\.\d+\.\d+)\.svg$/D', (string) $file, $f), (string) $file . ': no other file in .github/badges');
            self::assertStringContainsString("aria-label=\"packagist: v{$f[1]}\"", self::read('.github/badges/' . $file), (string) $file);
        }

        $badges = [
            "packagist-v{$version}.svg" => ['packagist', 'v' . $version, '#007ec6'],
            'license.svg' => ['license', $license, '#ea7233'],
        ];
        foreach ($badges as $file => [$label, $value, $colour]) {
            $svg = self::read('.github/badges/' . $file);
            self::assertStringStartsWith('<svg xmlns="http://www.w3.org/2000/svg" ', $svg, $file);
            self::assertLessThan(4096, strlen($svg), $file);
            self::assertStringContainsString("aria-label=\"{$label}: {$value}\"", $svg, $file);
            self::assertStringContainsString("<title>{$label}: {$value}</title>", $svg, $file);
            self::assertSame(3, substr_count($svg, ">{$label}</text>"), $file);
            self::assertSame(3, substr_count($svg, ">{$value}</text>"), $file . ' names ' . $value);
            self::assertStringContainsString("fill=\"{$colour}\"", $svg, $file);
            self::assertSame(0, preg_match('/<script|<foreignObject|href|\son[a-z]+=|url\((?!#)/i', $svg), $file . ': a plain image');
        }
    }
}

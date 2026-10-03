# MIME Shield – Releasing

Release process decided in the security audit (audit I-05 decision 2026-10-03): releases are
signed annotated Git tags built by a green CI run, distributed through Packagist, and installed by
version constraint. `dev-main` is for development only.

## 1. Checklist

1. **CI is green** on `main` for the commit to be released (`.github/workflows/ci.yml`: PHPUnit on
   PHP 8.1–8.5 with the Roundcube library, `php -l`, `node --check`, PHPStan level 6). Run the
   release checks CI cannot run (E2E, browser UI, interop; see docs/TESTING.md) and record them there.
2. **CHANGELOG.md**: rename `## [Unreleased]` to `## [X.Y.Z] – YYYY-MM-DD` (semantic versioning;
   any security fix is at least a patch release), add a new empty `## [Unreleased]`, commit.
3. **Signed annotated tag** on that commit:

   ```sh
   # GPG key
   git tag -s vX.Y.Z -m "MIME Shield X.Y.Z"
   # or an SSH signing key (Git >= 2.34)
   git config gpg.format ssh
   git config user.signingkey ~/.ssh/id_ed25519.pub
   git tag -s vX.Y.Z -m "MIME Shield X.Y.Z"
   ```

   Never use a lightweight or unsigned tag for a release.
4. **Verify** before publishing: `git tag -v vX.Y.Z` (for SSH signatures configure
   `gpg.ssh.allowedSignersFile`, see section 3).
5. **Push the tag**: `git push origin vX.Y.Z` (the commit must already be on `main`).
6. **GitHub release** from the tag (`gh release create vX.Y.Z --verify-tag --notes-file <notes>`),
   notes = the CHANGELOG section of the version.
7. **Packagist**: submit `https://github.com/takenek/mimeshield` once at packagist.org and enable
   the GitHub hook (Packagist "GitHub Service Hook" / sync), so new tags are published automatically.
   Check that the version appears on packagist.org/packages/takenek/mimeshield.

## 2. Installation by version

Administrators install a tagged release, never `dev-main`:

```sh
composer require "takenek/mimeshield:^X.Y"
```

`composer update` then stays within the major version; review CHANGELOG.md before upgrading.

## 3. Verifying a tag signature

```sh
git clone https://github.com/takenek/mimeshield && cd mimeshield
git tag -v vX.Y.Z          # GPG: import the maintainer's public key first
# SSH-signed tags: list the maintainer's public signing key in an allowed-signers file
echo "<maintainer e-mail> ssh-ed25519 AAAA..." > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v vX.Y.Z
```

Obtain the maintainer's key from a channel independent of the repository (e.g. the key published
in the maintainer's GitHub profile, `https://github.com/<user>.gpg` / `.keys`), and compare the
tagged commit with the one Composer installed (`composer show takenek/mimeshield`, field "source").

## 4. Release archive contents

The archive GitHub and Packagist serve (`git archive`) honours `export-ignore` in `.gitattributes`:
the test suite (including the TEST-ONLY PKI), CI configuration (`.github/`), developer tooling
configuration and security audit working documents are not part of a release. Check with
`git archive vX.Y.Z | tar -t` before publishing.

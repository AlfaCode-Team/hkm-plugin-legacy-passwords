<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Infrastructure\Cli;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use Plugins\LegacyPasswords\API\Contracts\LegacyPasswordContract;
use Plugins\LegacyPasswords\Domain\Algorithms\Argon2Hash;
use Plugins\LegacyPasswords\Domain\Algorithms\Pbkdf2Hash;
use Plugins\LegacyPasswords\Domain\Algorithms\Phpass;
use Plugins\LegacyPasswords\Domain\HashDetector;
use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;

/**
 * `legacy:inspect` — say what a stored hash is, and optionally test one.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE DISASTER THIS COMMAND EXISTS TO PREVENT
 * ════════════════════════════════════════════════════════════════════════════
 *
 * An import of 50,000 users with the salt placement declared the wrong way
 * round produces 50,000 rows that look perfect and verify nothing. The symptom
 * is not an error — it is every migrated user being told their password is
 * incorrect, support concluding they all forgot, and the real cause surfacing
 * a fortnight later.
 *
 * The fix costs one command: take ONE account whose password is known, run it
 * through here, and confirm the declaration before the other 49,999 rows are
 * written. That is the whole purpose.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THE PASSWORD IS READ FROM STDIN, NEVER FROM argv
 * ────────────────────────────────────────────────────────────────────────────
 *
 * A password in `argv` is visible to every other process on the machine
 * through `ps`, and it is written verbatim into the shell's history file. So
 * there is no `--password` option, and there deliberately never will be.
 *
 * `AbstractCommand::ask()` is also not used: it ECHOES, which would print the
 * password to the terminal and into any captured session log. php-io-cli does
 * have a masked `Password` component, but it is interactive-only and this
 * command has to work inside a migration script, so STDIN is the one input
 * that is correct in both cases.
 *
 *     printf '%s' "$KNOWN_PASSWORD" | hkm cli legacy:inspect '$P$B…' --verify
 *
 * ────────────────────────────────────────────────────────────────────────────
 * IT CAN ONLY VERIFY A SELF-DESCRIBING HASH
 * ────────────────────────────────────────────────────────────────────────────
 *
 * A bare digest needs an algorithm, a salt, a salt POSITION, an encoding and
 * possibly N, r and p — none of which fit on a command line without becoming
 * a second configuration format that nothing else reads. For those, the
 * command reports what it can (the length, and what that length is consistent
 * with) and says plainly that verification needs a declared credential in
 * code.
 */
final class InspectHashCommand extends AbstractCommand
{
    /**
     * @param resource|null $input Where to read the password from. Null means
     *                             `STDIN`, which is the only value production
     *                             ever passes.
     *
     * The seam exists so the `--verify` path can be TESTED. Without it the
     * command's only testable half would be the half that prints a table, and
     * the half that decides whether a password matches — the half an operator
     * acts on — would ship having never run. A `php://memory` stream in a test
     * is a smaller price than that.
     */
    public function __construct(
        private readonly LegacyPasswordContract $legacy,
        private readonly mixed $input = null,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->name        = 'legacy:inspect';
        $this->description = 'Identify a legacy password hash, and optionally verify one password against it.';

        $this->addArgument('hash', 'The stored hash, exactly as the column holds it.', true);
        $this->addOption(
            'verify',
            '',
            'Read a password from STDIN and test it against the hash. Never pass a password as an argument.',
        );
    }

    protected function handle(): int
    {
        $hash = (string) $this->argument('hash', '');

        if ($hash === '') {
            $this->error('No hash given.');

            return self::FAILURE;
        }

        $this->section('Hash');
        $this->report($hash);

        $algorithm = HashDetector::algorithm($hash);

        if ($algorithm === null) {
            $this->bareGuidance($hash);

            // Non-zero when a verification was ASKED FOR and cannot be done.
            // Merely inspecting an unrecognised hash is a successful answer —
            // "this is bare" is the correct result, not a failure.
            return $this->option('verify') ? self::FAILURE : self::SUCCESS;
        }

        if (!$this->option('verify')) {
            $this->newLine();
            $this->muted('Pass --verify with a password on STDIN to test it.');

            return self::SUCCESS;
        }

        return $this->verify($hash);
    }

    private function report(string $hash): void
    {
        $algorithm  = HashDetector::algorithm($hash);
        $wellFormed = $algorithm !== null && HashDetector::isWellFormed($hash, $algorithm);

        // `supported()` answers for Argon2 as a FAMILY, and that is not the
        // question here. PHP exposes only argon2i and argon2id, so an
        // `$argon2d$` hash reported this line as "yes" until the variant was
        // checked too — found by running the command rather than by reading it.
        $supported = $algorithm !== null
            && \in_array($algorithm, $this->legacy->supported(), true)
            && ($algorithm !== LegacyAlgorithm::Argon2
                || Argon2Hash::parse($hash)?->verifiableHere() === true);

        $rows = [
            ['Length', (string) \strlen($hash)],
            ['Detected', $algorithm?->value ?? 'not self-describing'],
            ['Scheme', $algorithm?->explain() ?? '—'],
            ['Well formed', $algorithm === null ? '—' : ($wellFormed ? 'yes' : 'NO')],
            ['This build can verify it', $algorithm === null ? '—' : ($supported ? 'yes' : 'NO')],
            ['Work factor', $this->workFactor($hash, $algorithm)],
        ];

        $this->table()->headers(['Property', 'Value'])->rows($rows)->render();

        if ($algorithm !== null && !$wellFormed) {
            $this->newLine();
            $this->warning(
                'The prefix says ' . $algorithm->value . ' but the rest does not parse. That is a '
                . 'TRUNCATED OR CORRUPTED column, not a wrong password — and it will fail for every '
                . 'row of the same shape. Check the column width the import wrote into.',
            );
        }
    }

    private function workFactor(string $hash, ?LegacyAlgorithm $algorithm): string
    {
        return match ($algorithm) {
            LegacyAlgorithm::Bcrypt => $this->describeOptions($hash),

            // NOT describeOptions(). `password_get_info()` returns an empty
            // options array for argon2d — a variant it cannot verify — so this
            // line read "unreadable" for a hash whose parameters are perfectly
            // legible. Found by running the command.
            LegacyAlgorithm::Argon2
                => ($a = Argon2Hash::parse($hash)) === null
                    ? 'unreadable'
                    : \sprintf(
                        '%s, m=%d KiB, t=%d, p=%d',
                        $a->variant,
                        $a->memoryCost,
                        $a->timeCost,
                        $a->parallelism,
                    ),

            LegacyAlgorithm::Phpass
                => ($i = Phpass::iterations($hash)) === null
                    ? 'unreadable'
                    : $i . ' iterations of MD5',
            LegacyAlgorithm::Pbkdf2
                => ($p = Pbkdf2Hash::parse($hash)) === null
                    ? 'unreadable'
                    : $p->iterations . ' iterations of HMAC-' . strtoupper($p->digest),
            LegacyAlgorithm::Crypt
                => preg_match('/^\$[56]\$rounds=(\d+)\$/', $hash, $m) === 1
                    ? $m[1] . ' rounds'
                    : 'the scheme default (1,000 for $1$, 5,000 for $5$/$6$)',
            null => '—',
            default => 'declared out of band, not in the hash',
        };
    }

    private function describeOptions(string $hash): string
    {
        $info    = password_get_info($hash);
        $options = $info['options'] ?? [];

        if ($options === []) {
            return 'unreadable';
        }

        $parts = [];

        foreach ($options as $key => $value) {
            $parts[] = $key . '=' . (\is_scalar($value) ? (string) $value : '?');
        }

        return implode(' ', $parts);
    }

    /**
     * What to do with a hash that does not identify itself.
     *
     * Deliberately does NOT guess. It reports which allowed algorithms produce
     * a digest of this length in each encoding, which narrows the field
     * without pretending to have decided — and then says the thing that
     * actually matters, which is that the salt's position has to come from
     * reading the old application's source.
     */
    private function bareGuidance(string $hash): void
    {
        $this->newLine();
        $this->section('This hash does not say what it is');

        $this->info(
            'No recognised prefix, so it is a BARE digest: the algorithm, the salt and the '
            . 'salt\'s position live outside this string.',
        );
        $this->newLine();

        $length     = \strlen($hash);
        $candidates = [];

        foreach (\Plugins\LegacyPasswords\Domain\DigestParameters::ALLOWED as $name => $bytes) {
            foreach (\Plugins\LegacyPasswords\Domain\DigestEncoding::cases() as $encoding) {
                if ($encoding->lengthFor($bytes) === $length) {
                    $candidates[] = $name . ' (' . $encoding->value . ')';
                }
            }
        }

        if ($candidates === []) {
            $this->warning(\sprintf(
                'No allowed digest algorithm produces %d characters in any encoding. That points at '
                . 'a truncated column, a prefix this build does not know, or something that is not '
                . 'a password hash at all.',
                $length,
            ));
        } else {
            $this->muted(\sprintf('%d characters is consistent with: %s', $length, implode(', ', $candidates)));
            $this->newLine();
            $this->warning(
                'That list is NOT a diagnosis. The length narrows the algorithm and says nothing '
                . 'about the salt — and whether the salt went before or after the password cannot '
                . 'be recovered from the digest at any cost. Read the old login code.',
            );
        }

        $this->newLine();
        $this->muted(
            'Declare it in code with LegacyCredential::digest(), ::scrypt() or '
            . '::firebaseScrypt(), then test it against one account whose password you know.',
        );
    }

    private function verify(string $hash): int
    {
        $password = $this->readPassword();

        if ($password === null) {
            $this->error(
                'No password on STDIN. Pipe one in — `printf \'%s\' "$PW" | hkm cli legacy:inspect … '
                . '--verify`. There is no --password option on purpose: an argument is visible in '
                . '`ps` and lands in the shell history.',
            );

            return self::FAILURE;
        }

        $credential = HashDetector::detect($hash);

        // Unreachable: the caller already established the algorithm is
        // detectable. Guarded so a future change to detect() cannot turn this
        // into a null dereference.
        if ($credential === null) {
            $this->error('The hash is not self-describing, so it cannot be verified here.');

            return self::FAILURE;
        }

        $this->newLine();
        $this->section('Verification');

        $verdict = $this->legacy->verify($password, $credential);

        if ($verdict->verified) {
            $this->success('The password matches.');
            $this->newLine();
            $this->warning(
                'Now make sure the login path calls upgrade() and STORES the result. A legacy hash '
                . 'can only ever be replaced during a login, because that is the only moment the '
                . 'plaintext exists — skip it and every future login pays this cost again.',
            );

            return self::SUCCESS;
        }

        $this->error('Refused: ' . ($verdict->refusal?->explain() ?? 'unknown reason'));

        if ($verdict->suggestsMisconfiguration()) {
            $this->newLine();
            $this->warning(
                'This is a DEPLOYMENT problem, not a wrong password — it will affect every row of '
                . 'the same shape, so no migrated user will be able to log in until it is fixed.',
            );
        }

        return self::FAILURE;
    }

    /**
     * Read the password from STDIN, or null when nothing was piped in.
     *
     * A trailing newline is stripped because `echo` adds one and `printf` does
     * not, and a password that silently differs by one byte depending on which
     * the operator used is the worst possible way for this command to lie. The
     * cost is that a password genuinely ending in a newline cannot be tested
     * here — which is stated rather than hidden, and is not a password any
     * login form can produce.
     */
    private function readPassword(): ?string
    {
        $stream = \is_resource($this->input) ? $this->input : \STDIN;

        if (stream_isatty($stream)) {
            // Nothing was piped. Prompting is not an option: ask() echoes, and
            // the masked component cannot be reached from here.
            return null;
        }

        $input = stream_get_contents($stream);

        if ($input === false || $input === '') {
            return null;
        }

        return preg_replace('/\r?\n$/D', '', $input) ?? $input;
    }
}

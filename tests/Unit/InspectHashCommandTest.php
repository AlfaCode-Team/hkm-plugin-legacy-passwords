<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use AlfacodeTeam\PhpIoCli\AbstractCommand;
use AlfacodeTeam\PhpIoCli\BufferIO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Application\Services\LegacyPasswordService;
use Plugins\LegacyPasswords\Infrastructure\Cli\InspectHashCommand;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;
use Tests\Plugins\LegacyPasswords\Support\RecordingHasher;
use Tests\Plugins\LegacyPasswords\Support\Vectors;

/**
 * The command, actually executed.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * WHY THIS FILE EXISTS
 * ════════════════════════════════════════════════════════════════════════════
 *
 * Running the command found a real defect that reading it had not: an
 * `$argon2d$` hash reported "This build can verify it: yes" and
 * "Work factor: unreadable". Both were wrong — the support check was
 * family-level, and the work factor came from `password_get_info()`, which
 * returns an empty options array for the one Argon2 variant PHP cannot verify.
 *
 * That is the argument for this file in one sentence: a command that is only
 * read is a command that has not been tested.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * ONE CAPTURE QUIRK, WHICH IS THE HARNESS AND NOT THE COMMAND
 * ────────────────────────────────────────────────────────────────────────────
 *
 * `Table::render()` writes to STDOUT directly rather than through the
 * `IOInterface`, so in a `BufferIO` capture the table and the surrounding text
 * arrive on different channels and appear out of order. In a real terminal
 * both go to the same place in the right order. The assertions below therefore
 * test the table's CONTENT via output buffering and the prose via the buffer,
 * rather than asserting on their relative order.
 */
final class InspectHashCommandTest extends TestCase
{
    /**
     * @param resource|null $input
     * @return array{code: int, output: string}
     */
    private function runCommand(array $tokens, mixed $input = null): array
    {
        $service = new LegacyPasswordService(
            config: LegacyPasswordConfig::of(),
            hasher: new RecordingHasher(),
        );

        $command = new InspectHashCommand($service, $input);
        $io      = new BufferIO();

        // The table bypasses IOInterface, so capture STDOUT too and join the
        // two — otherwise half the command's output is invisible here.
        ob_start();
        $code    = $command->execute($tokens, $io);
        $direct  = (string) ob_get_clean();

        $output = $direct . "\n" . $io->getOutput();

        // Strip ANSI so assertions are about words rather than colour codes.
        return [
            'code'   => $code,
            'output' => (string) preg_replace('/\e\[[0-9;]*m/', '', $output),
        ];
    }

    /** @param string[] $expectedFragments */
    #[DataProvider('inspections')]
    public function test_it_identifies_a_hash(string $hash, array $expectedFragments): void
    {
        $result = $this->runCommand([$hash]);

        self::assertSame(AbstractCommand::SUCCESS, $result['code']);

        foreach ($expectedFragments as $fragment) {
            self::assertStringContainsString($fragment, $result['output']);
        }
    }

    /** @return iterable<string, array{string, string[]}> */
    public static function inspections(): iterable
    {
        yield 'phpass' => [
            '$P$Be.39vipNM3QIErUZ.CevixuseSbRo0',
            ['phpass', '8192 iterations of MD5'],
        ];

        yield 'bcrypt' => [
            password_hash('secret', \PASSWORD_BCRYPT, ['cost' => 4]),
            ['bcrypt', 'cost=4'],
        ];

        yield 'sha512-crypt with rounds' => [
            crypt('secret', '$6$rounds=5000$abcdefghijklmnop$'),
            ['crypt', '5000 rounds'],
        ];

        yield 'django pbkdf2' => [
            'pbkdf2_sha256$100$saltysalt$bnZcguu4i5mSMhgogBqYtgqcxie6nyLTBPwwoODDBG8=',
            ['pbkdf2', '100 iterations of HMAC-SHA256'],
        ];
    }

    /**
     * THE DEFECT RUNNING IT FOUND.
     *
     * argon2d is a valid format PHP cannot verify. The command must say so —
     * and must still report the work factor, which is perfectly legible in the
     * string even though `password_get_info()` returns nothing for it.
     */
    public function test_argon2d_is_reported_as_unverifiable_with_its_real_work_factor(): void
    {
        $result = $this->runCommand(['$argon2d$v=19$m=65536,t=4,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNo']);

        self::assertStringContainsString('argon2d, m=65536 KiB, t=4, p=1', $result['output']);
        self::assertStringNotContainsString('unreadable', $result['output']);

        // The support column. Asserted via the row label so a layout change
        // does not silently stop testing it.
        self::assertMatchesRegularExpression(
            '/This build can verify it\s*\S*\s*NO/',
            $result['output'],
            'argon2d must not be reported as verifiable',
        );
    }

    public function test_a_truncated_hash_is_called_out_as_a_broken_import(): void
    {
        $result = $this->runCommand(['$2y$12$tooshort']);

        self::assertStringContainsString('TRUNCATED OR CORRUPTED column', $result['output']);
        self::assertStringContainsString('not a wrong password', $result['output']);
    }

    /**
     * A bare digest gets guidance, and the guidance refuses to diagnose.
     *
     * The length narrows the algorithm; it says nothing about the salt. Saying
     * so explicitly is the difference between a useful tool and one that
     * encourages a guess.
     */
    public function test_a_bare_digest_is_narrowed_but_never_diagnosed(): void
    {
        $result = $this->runCommand([md5('secret')]);

        self::assertSame(AbstractCommand::SUCCESS, $result['code']);
        self::assertStringContainsString('does not say what it is', $result['output']);
        self::assertStringContainsString('md5 (hex_lower)', $result['output']);
        self::assertStringContainsString('NOT a diagnosis', $result['output']);
        self::assertStringContainsString('Read the old login code', $result['output']);
    }

    public function test_a_length_no_algorithm_produces_is_reported_as_suspicious(): void
    {
        $result = $this->runCommand([str_repeat('a', 61)]);

        self::assertStringContainsString('No allowed digest algorithm produces 61 characters', $result['output']);
    }

    // ── the --verify path ───────────────────────────────────────────────────

    public function test_verify_accepts_the_right_password_from_stdin(): void
    {
        $vector = Vectors::phpass()[0];
        $result = $this->runCommand(
            [$vector['hash'], '--verify'],
            $this->stream($vector['password']),
        );

        self::assertSame(AbstractCommand::SUCCESS, $result['code']);
        self::assertStringContainsString('The password matches', $result['output']);
        // The reminder that matters more than the result.
        self::assertStringContainsString('upgrade()', $result['output']);
    }

    public function test_verify_rejects_the_wrong_password(): void
    {
        $vector = Vectors::phpass()[0];
        $result = $this->runCommand(
            [$vector['hash'], '--verify'],
            $this->stream('not-the-password'),
        );

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
        self::assertStringContainsString('did not match the stored hash', $result['output']);
        // A wrong password is NOT a deployment problem, so the operator
        // warning must be absent.
        self::assertStringNotContainsString('DEPLOYMENT problem', $result['output']);
    }

    /**
     * An operational refusal says so, loudly.
     *
     * A truncated hash will fail for every row of the same shape, so the
     * command must distinguish it from somebody mistyping — which is the whole
     * point of the refusal taxonomy.
     */
    public function test_verify_flags_an_operational_refusal_as_a_deployment_problem(): void
    {
        $result = $this->runCommand(['$2y$12$tooshort', '--verify'], $this->stream('secret'));

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
        self::assertStringContainsString('DEPLOYMENT problem', $result['output']);
    }

    /**
     * A trailing newline is stripped, because `echo` adds one and `printf`
     * does not.
     *
     * A password that silently differed by one byte depending on which the
     * operator used would be the worst possible way for this command to lie —
     * it would report "does not match" for the correct password.
     */
    #[DataProvider('newlineForms')]
    public function test_a_trailing_newline_from_the_shell_is_stripped(string $piped): void
    {
        $vector = Vectors::phpass()[0];
        $result = $this->runCommand([$vector['hash'], '--verify'], $this->stream($piped));

        self::assertSame(
            AbstractCommand::SUCCESS,
            $result['code'],
            'the password differed by its line ending, which is exactly what must not happen',
        );
    }

    /** @return iterable<string, array{string}> */
    public static function newlineForms(): iterable
    {
        $password = Vectors::phpass()[0]['password'];

        yield 'printf, no newline' => [$password];
        yield 'echo, trailing LF' => [$password . "\n"];
        yield 'Windows, trailing CRLF' => [$password . "\r\n"];
    }

    /**
     * Only ONE trailing newline is stripped.
     *
     * A password cannot end in a newline through any login form, so this is
     * about not silently eating more of the input than the shell added.
     */
    public function test_only_one_trailing_newline_is_stripped(): void
    {
        $vector = Vectors::phpass()[0];
        $result = $this->runCommand(
            [$vector['hash'], '--verify'],
            $this->stream($vector['password'] . "\n\n"),
        );

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
    }

    /**
     * No password on STDIN is an error naming the fix, not a prompt.
     *
     * There is no `--password` option and never will be: an argument is
     * visible to every process through `ps` and lands in the shell history.
     */
    public function test_verify_without_a_piped_password_explains_itself(): void
    {
        $result = $this->runCommand(['$P$Be.39vipNM3QIErUZ.CevixuseSbRo0', '--verify'], $this->stream(''));

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
        self::assertStringContainsString('No password on STDIN', $result['output']);
        self::assertStringContainsString('visible in', $result['output']);
    }

    /**
     * Asking to verify a BARE digest fails, because it cannot be done from a
     * command line.
     *
     * A bare digest needs an algorithm, a salt, a placement, an encoding and
     * possibly N, r and p. Accepting all of that as flags would be a second
     * configuration format nothing else reads.
     */
    public function test_verify_on_a_bare_digest_fails_rather_than_guessing(): void
    {
        $result = $this->runCommand([md5('secret'), '--verify'], $this->stream('secret'));

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
        self::assertStringContainsString('does not say what it is', $result['output']);
    }

    public function test_an_empty_hash_argument_fails(): void
    {
        $result = $this->runCommand(['']);

        self::assertSame(AbstractCommand::FAILURE, $result['code']);
        self::assertStringContainsString('No hash given', $result['output']);
    }

    public function test_the_command_declares_its_name(): void
    {
        $service = new LegacyPasswordService(config: LegacyPasswordConfig::of());
        $command = new InspectHashCommand($service);

        self::assertSame('legacy:inspect', $command->getName());
        self::assertNotSame('', $command->getDescription());
    }

    /**
     * The command never prints the password it was given.
     *
     * It is the one place in the plugin that handles a plaintext password and
     * also writes to a terminal, so the capture is asserted directly.
     */
    public function test_the_password_is_never_echoed(): void
    {
        $vector  = Vectors::phpass()[0];
        $secret  = 'a-very-recognisable-password';

        foreach ([$vector['password'], $secret] as $piped) {
            $result = $this->runCommand([$vector['hash'], '--verify'], $this->stream($piped));

            self::assertStringNotContainsString(
                $piped,
                $result['output'],
                'the command echoed the password it was piped',
            );
        }
    }

    /** @return resource */
    private function stream(string $contents): mixed
    {
        $stream = fopen('php://memory', 'r+');

        self::assertNotFalse($stream);

        fwrite($stream, $contents);
        rewind($stream);

        return $stream;
    }
}

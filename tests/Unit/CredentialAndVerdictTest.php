<?php

declare(strict_types=1);

namespace Tests\Plugins\LegacyPasswords\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\LegacyPasswords\Domain\DigestParameters;
use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;
use Plugins\LegacyPasswords\Domain\LegacyCredential;
use Plugins\LegacyPasswords\Domain\LegacyRefusal;
use Plugins\LegacyPasswords\Domain\LegacyVerdict;

final class CredentialAndVerdictTest extends TestCase
{
    /**
     * A stored hash must not appear in a debug dump.
     *
     * A password hash is not a credential — it cannot be replayed — but it is
     * exactly what an offline attacker wants, and for the weak schemes this
     * plugin exists to read, "offline attack" means seconds. An unsalted MD5
     * in an uncaught-exception dump is a password with a delay.
     */
    public function test_the_stored_hash_is_redacted_from_a_debug_dump(): void
    {
        $hash       = '5ebe2294ecd0e0f08eab7690d2a6ee69';
        $credential = LegacyCredential::digest($hash, DigestParameters::of('md5'));

        $dumped = print_r($credential->__debugInfo(), true);

        self::assertStringNotContainsString($hash, $dumped);
        self::assertStringContainsString('[redacted: 32 characters]', $dumped);

        // var_dump() is the call that actually happens in the wild, and it
        // honours __debugInfo(). Captured so this is tested rather than
        // assumed.
        ob_start();
        var_dump($credential);
        $output = (string) ob_get_clean();

        self::assertStringNotContainsString($hash, $output);
    }

    public function test_describe_carries_no_hash(): void
    {
        $hash       = '5ebe2294ecd0e0f08eab7690d2a6ee69';
        $credential = LegacyCredential::digest($hash, DigestParameters::of('md5'));

        $described = json_encode($credential->describe());

        self::assertIsString($described);
        self::assertStringNotContainsString($hash, $described);
        self::assertStringContainsString('"stored_length":32', $described);
        self::assertStringContainsString('"work_factored":false', $described);
    }

    /**
     * `label()` is the one string that may go in a message, so it must carry
     * the algorithm and the length and nothing else.
     */
    public function test_the_label_is_safe_to_print(): void
    {
        $hash  = '5ebe2294ecd0e0f08eab7690d2a6ee69';
        $label = LegacyCredential::digest($hash, DigestParameters::of('md5'))->label();

        self::assertSame('digest/32ch', $label);
        self::assertStringNotContainsString($hash, $label);
    }

    /**
     * Every named constructor sets the algorithm it says it does.
     *
     * The type system already prevents a scrypt credential without its
     * parameters, so what is left to get wrong is a copy-paste in the
     * constructor list — which this catches.
     */
    public function test_each_named_constructor_sets_its_own_algorithm(): void
    {
        self::assertSame(LegacyAlgorithm::Bcrypt, LegacyCredential::bcrypt('x')->algorithm);
        self::assertSame(LegacyAlgorithm::Argon2, LegacyCredential::argon2('x')->algorithm);
        self::assertSame(LegacyAlgorithm::Crypt, LegacyCredential::crypt('x')->algorithm);
        self::assertSame(LegacyAlgorithm::Phpass, LegacyCredential::phpass('x')->algorithm);
        self::assertSame(LegacyAlgorithm::Pbkdf2, LegacyCredential::pbkdf2('x')->algorithm);
        self::assertSame(LegacyAlgorithm::Plaintext, LegacyCredential::plaintext('x')->algorithm);
        self::assertSame(
            LegacyAlgorithm::Digest,
            LegacyCredential::digest('x', DigestParameters::of('md5'))->algorithm,
        );
    }

    public function test_an_empty_stored_value_is_reported_as_empty(): void
    {
        self::assertTrue(LegacyCredential::bcrypt('')->isEmpty());
        self::assertFalse(LegacyCredential::bcrypt('x')->isEmpty());
    }

    // ── the enums ───────────────────────────────────────────────────────────

    /**
     * Only the five self-describing schemes claim to be self-describing.
     *
     * This flag is what keeps the detector and the declaration paths apart, so
     * a wrong answer here would either make a bare digest detectable (which is
     * the guessing this plugin refuses to do) or make a bcrypt hash need
     * parameters it does not have.
     */
    public function test_exactly_the_right_schemes_are_self_describing(): void
    {
        $selfDescribing = array_values(array_filter(
            LegacyAlgorithm::cases(),
            static fn (LegacyAlgorithm $a): bool => $a->selfDescribing(),
        ));

        self::assertSame(
            [
                LegacyAlgorithm::Bcrypt,
                LegacyAlgorithm::Argon2,
                LegacyAlgorithm::Crypt,
                LegacyAlgorithm::Phpass,
                LegacyAlgorithm::Pbkdf2,
            ],
            $selfDescribing,
        );
    }

    /**
     * Digest and plaintext are the only schemes with no work factor at all.
     *
     * The flag drives what a migration report says, and it is the honest
     * answer rather than a flattering one — "digest" sounds respectable, and
     * a single unsalted pass of MD5 is not.
     */
    public function test_only_digest_and_plaintext_have_no_work_factor(): void
    {
        $unfactored = array_values(array_filter(
            LegacyAlgorithm::cases(),
            static fn (LegacyAlgorithm $a): bool => !$a->workFactored(),
        ));

        self::assertSame([LegacyAlgorithm::Digest, LegacyAlgorithm::Plaintext], $unfactored);
    }

    public function test_every_algorithm_explains_itself(): void
    {
        foreach (LegacyAlgorithm::cases() as $case) {
            self::assertNotSame('', $case->explain(), $case->value . ' has no explanation');
        }
    }

    /**
     * Only a wrong password is NOT a misconfiguration.
     *
     * Everything else means a population cannot log in and nobody has been
     * told, which is the distinction a caller routes on — an error to an
     * operator versus a line in an access log.
     */
    public function test_only_a_wrong_password_is_not_operational(): void
    {
        foreach (LegacyRefusal::cases() as $case) {
            self::assertSame(
                $case !== LegacyRefusal::WrongPassword,
                $case->suggestsMisconfiguration(),
                $case->value . ' is classified wrongly',
            );
            self::assertNotSame('', $case->explain());
        }
    }

    public function test_a_granted_verdict_always_demands_an_upgrade(): void
    {
        foreach (LegacyAlgorithm::cases() as $case) {
            $verdict = LegacyVerdict::granted($case);

            self::assertTrue($verdict->verified);
            self::assertNull($verdict->refusal);
            // No condition, for any scheme. There is no "good enough" legacy
            // hash — the whole premise is that it should not be there.
            self::assertTrue($verdict->mustUpgrade());
            self::assertFalse($verdict->suggestsMisconfiguration());
        }
    }

    public function test_a_refused_verdict_never_demands_an_upgrade(): void
    {
        foreach (LegacyRefusal::cases() as $refusal) {
            $verdict = LegacyVerdict::refused(LegacyAlgorithm::Bcrypt, $refusal);

            self::assertFalse($verdict->verified);
            self::assertFalse($verdict->mustUpgrade());
            self::assertSame($refusal, $verdict->refusal);
        }
    }

    /**
     * A log line carries the algorithm and never a hash or a password.
     *
     * The algorithm is deliberate: knowing that some accounts are on unsalted
     * MD5 is the number an operator watches go to zero during a migration, and
     * it is not a secret from anyone who already holds the database.
     */
    #[DataProvider('verdicts')]
    public function test_a_log_line_is_structured_and_safe(LegacyVerdict $verdict): void
    {
        $line = $verdict->logLine();

        self::assertStringContainsString('algorithm=', $line);
        self::assertStringNotContainsString('$', $line, 'a $ would be the start of a leaked hash');
        // One line, so it cannot forge a second entry in a log file.
        self::assertStringNotContainsString("\n", $line);
        self::assertStringNotContainsString("\r", $line);
    }

    /** @return iterable<string, array{LegacyVerdict}> */
    public static function verdicts(): iterable
    {
        foreach (LegacyAlgorithm::cases() as $algorithm) {
            yield 'granted ' . $algorithm->value => [LegacyVerdict::granted($algorithm)];
        }

        foreach (LegacyRefusal::cases() as $refusal) {
            yield 'refused ' . $refusal->value => [
                LegacyVerdict::refused(LegacyAlgorithm::Digest, $refusal),
            ];
        }
    }
}

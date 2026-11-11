<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\HashingPort;
use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\LoggerPort;
use Plugins\LegacyPasswords\API\Contracts\LegacyPasswordContract;
use Plugins\LegacyPasswords\Domain\Algorithms\Argon2Hash;
use Plugins\LegacyPasswords\Domain\Algorithms\FirebaseScrypt;
use Plugins\LegacyPasswords\Domain\Algorithms\Pbkdf2Hash;
use Plugins\LegacyPasswords\Domain\Algorithms\Phpass;
use Plugins\LegacyPasswords\Domain\Algorithms\Scrypt;
use Plugins\LegacyPasswords\Domain\DigestEncoding;
use Plugins\LegacyPasswords\Domain\DigestParameters;
use Plugins\LegacyPasswords\Domain\FirebaseParameters;
use Plugins\LegacyPasswords\Domain\HashDetector;
use Plugins\LegacyPasswords\Domain\LegacyAlgorithm;
use Plugins\LegacyPasswords\Domain\LegacyCredential;
use Plugins\LegacyPasswords\Domain\LegacyRefusal;
use Plugins\LegacyPasswords\Domain\LegacyVerdict;
use Plugins\LegacyPasswords\Domain\ScryptParameters;
use Plugins\LegacyPasswords\Infrastructure\Config\LegacyPasswordConfig;

/**
 * Verifies a password against a foreign hash, and mints its replacement.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE ORDER OF THE CHECKS IS THE SECURITY PROPERTY
 * ════════════════════════════════════════════════════════════════════════════
 *
 * 1. An EMPTY stored value is refused before anything else. A NULL or blank
 *    password column is common in an import — users who never set one, or rows
 *    where the column did not come across — and several of the schemes below
 *    would happily verify something against it. An unsalted MD5 of the empty
 *    string is a known constant; `hash_equals('', '')` is true. So this is the
 *    first check and it has no path past it.
 *
 * 2. PLAINTEXT is refused unless deliberately enabled, before the comparison
 *    rather than after, so a disabled deployment never compares at all.
 *
 * 3. WELL-FORMEDNESS, which separates "this import is broken" from "this user
 *    mistyped". Same observable outcome, completely different cause, and
 *    collapsing them is how a broken import stays invisible for weeks.
 *
 * 4. The WORK FACTOR CEILING, before the work is done. This is the whole point
 *    of having one: a `$2y$31$` hash planted in an untrusted import file is
 *    hours of CPU per login attempt, and checking afterwards would mean doing
 *    the hours first.
 *
 * 5. Only then the actual verification.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * EXACTLY ONE `hash_equals` IN THE WHOLE PLUGIN
 * ────────────────────────────────────────────────────────────────────────────
 *
 * Every algorithm class RECOMPUTES and returns a string; none of them
 * compares. The comparison happens once, in {@see matches()}, so there is one
 * line to get constant-time right and one line to review — rather than nine
 * comparisons, one of which someone eventually writes as `===` because it
 * reads more naturally.
 *
 * `===` on a hash comparison leaks the length of the matching prefix through
 * timing. For the work-factored schemes that is nearly unexploitable; for the
 * bare digest family, which is this plugin's main business, the attacker can
 * make millions of attempts a second against a local copy and the leak is
 * real.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * WHAT THIS SERVICE DOES NOT DO
 * ────────────────────────────────────────────────────────────────────────────
 *
 * It does not read or write a database — this plugin owns no table and
 * declares no migration. It does not decide whether the user may log in; it
 * answers one question about one hash. And it never produces a legacy hash:
 * there is no `make()` for any scheme here, deliberately, so nothing in a
 * project can reach for MD5 by accident. {@see upgrade()} delegates to the
 * application's own `HashingPort`.
 */
final class LegacyPasswordService implements LegacyPasswordContract
{
    public function __construct(
        private readonly LegacyPasswordConfig $config,
        /**
         * Null only on the CLI path, when a project wired `HashingPort` into
         * the request container and not the core.
         *
         * {@see verify()} and {@see detect()} do not need it — only
         * {@see upgrade()} does, and that throws with a message naming the fix
         * rather than failing on a null call. The alternative was for the
         * diagnostic command to refuse to register at all, which would hide it
         * at exactly the moment an import is going wrong.
         */
        private readonly ?HashingPort $hasher = null,
        /**
         * Optional. A migration's progress is only visible in logs — the
         * count of legacy verifications is the number an operator watches go
         * to zero — but a null logger must not stop a login working.
         */
        private readonly ?LoggerPort $logger = null,
    ) {}

    public function verify(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): LegacyVerdict {
        $verdict = $this->decide($password, $credential);

        $this->record($verdict);

        return $verdict;
    }

    public function detect(string $stored): ?LegacyCredential
    {
        return HashDetector::detect($stored);
    }

    public function upgrade(#[\SensitiveParameter] string $password): string
    {
        if ($this->hasher === null) {
            throw new \LogicException(
                'No HashingPort is available, so this service cannot mint a replacement hash. '
                . 'That happens when the service was built from the CoreContainer but the project '
                . 'bound HashingPort only into the request container — bind it in the bootstrap\'s '
                . 'withPorts([HashingPort::class => …]) instead. Verification works without it; '
                . 'only upgrade() needs it.',
            );
        }

        // The application's configured hasher, with the application's cost.
        // This plugin holds no opinion about what new passwords should be
        // hashed with — a second opinion here would mean a project that moved
        // to Argon2 silently got bcrypt for every migrated user.
        return $this->hasher->make($password);
    }

    /** @return list<LegacyAlgorithm> */
    public function supported(): array
    {
        $supported = [
            // Always: password_verify handles every bcrypt variant, and the
            // pure-PHP implementations need no extension.
            LegacyAlgorithm::Bcrypt,
            LegacyAlgorithm::Phpass,
            LegacyAlgorithm::Pbkdf2,
            LegacyAlgorithm::Scrypt,
            LegacyAlgorithm::Digest,
        ];

        // Argon2 is a compile-time option. `password_algos()` is the honest
        // check — PASSWORD_ARGON2ID is defined on builds that cannot actually
        // use it, so testing the constant would claim support that is not
        // there.
        if (\in_array('argon2id', password_algos(), true)
            || \in_array('argon2i', password_algos(), true)
        ) {
            $supported[] = LegacyAlgorithm::Argon2;
        }

        // crypt() always exists, but the ALGORITHMS inside it are build
        // options. Any one of the three modular variants is enough to be
        // useful.
        if (\defined('CRYPT_MD5') || \defined('CRYPT_SHA256') || \defined('CRYPT_SHA512')) {
            $supported[] = LegacyAlgorithm::Crypt;
        }

        // The Firebase path needs OpenSSL's AES-256-CTR. Checked against the
        // cipher list rather than assumed from `extension_loaded('openssl')`:
        // a FIPS-restricted build has the extension and not the cipher.
        if (\function_exists('openssl_encrypt')
            && \in_array('aes-256-ctr', openssl_get_cipher_methods(), true)
        ) {
            $supported[] = LegacyAlgorithm::FirebaseScrypt;
        }

        if ($this->config->allowPlaintext) {
            $supported[] = LegacyAlgorithm::Plaintext;
        }

        return $supported;
    }

    public function describe(): string
    {
        $parts = [];

        foreach ($this->config->describe() as $key => $value) {
            $parts[] = $key . '=' . (\is_bool($value) ? ($value ? 'yes' : 'no') : (string) $value);
        }

        $parts[] = 'supported=' . implode(
            ',',
            array_map(static fn (LegacyAlgorithm $a): string => $a->value, $this->supported()),
        );

        return implode(' ', $parts);
    }

    /**
     * The decision, with no logging — so the ordering above is readable in one
     * function and the logging cannot change it.
     */
    private function decide(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): LegacyVerdict {
        $algorithm = $credential->algorithm;

        // CHECK 1. See the class docblock — several schemes below would verify
        // against an empty stored value, and one of them would verify against
        // ANY password.
        if ($credential->isEmpty()) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::MalformedHash);
        }

        // CHECK 2. Before the comparison, not after.
        if ($algorithm === LegacyAlgorithm::Plaintext && !$this->config->allowPlaintext) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::PlaintextRefused);
        }

        if (!\in_array($algorithm, $this->supported(), true)) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::Unsupported);
        }

        // CHECK 3. Malformed is not "wrong password".
        if (!HashDetector::isWellFormed($credential->stored(), $algorithm)) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::MalformedHash);
        }

        // CHECK 3a. The bare schemes' well-formedness, which is their LENGTH.
        //
        // `HashDetector::isWellFormed()` answers true for every bare scheme,
        // because a bare digest has no shape to check — only its declared
        // parameters can say how long it should be, and the detector does not
        // have them. This does.
        //
        // A REVERT CHECK IS WHAT FOUND THIS. The length check used to live
        // inside checkDigest(), where it returned `false` — which the caller
        // turned into WrongPassword, the exact verdict the check's own comment
        // said it existed to avoid. Removing it therefore changed nothing
        // observable and the suite stayed green, which is how a guard that
        // reports the wrong thing survives review. Here it produces
        // MalformedHash, so a truncated column or a misdeclared algorithm
        // reaches an operator instead of being filed as a forgotten password
        // by every affected user.
        if (!$this->storedLengthMatchesParameters($credential)) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::MalformedHash);
        }

        // CHECK 3b. The VARIANT, which the coarse check above cannot see.
        //
        // `supported()` answers for Argon2 as a family, but PHP exposes only
        // argon2i and argon2id — never argon2d. An `$argon2d$` hash is
        // perfectly valid and simply uncheckable here, so reporting it as
        // malformed would send an operator hunting for a corrupt import that
        // does not exist. The hash is fine; this build cannot verify it.
        if ($algorithm === LegacyAlgorithm::Argon2
            && Argon2Hash::parse($credential->stored())?->verifiableHere() !== true
        ) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::Unsupported);
        }

        // CHECK 4. Before spending the work factor, never after.
        if (!$this->costIsAcceptable($credential)) {
            return LegacyVerdict::refused($algorithm, LegacyRefusal::CostRefused);
        }

        // CHECK 5.
        return $this->check($password, $credential);
    }

    private function check(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): LegacyVerdict {
        $algorithm = $credential->algorithm;
        $stored    = $credential->stored();

        $verified = match ($algorithm) {
            // PHP's own, which is constant-time internally and reads the
            // variant, cost and salt out of the string. Re-implementing
            // either would be strictly worse.
            LegacyAlgorithm::Bcrypt, LegacyAlgorithm::Argon2
                => password_verify($password, $stored),

            LegacyAlgorithm::Crypt  => $this->checkCrypt($password, $stored),
            LegacyAlgorithm::Phpass => $this->matches(
                Phpass::recompute($password, $stored),
                $stored,
            ),
            LegacyAlgorithm::Pbkdf2         => $this->checkPbkdf2($password, $stored),
            LegacyAlgorithm::Scrypt         => $this->checkScrypt($password, $credential),
            LegacyAlgorithm::FirebaseScrypt => $this->checkFirebase($password, $credential),
            LegacyAlgorithm::Digest         => $this->checkDigest($password, $credential),
            // Reached only when allowPlaintext is true — CHECK 2 refuses it
            // otherwise, before this method is called.
            LegacyAlgorithm::Plaintext      => $this->matches($password, $stored),
        };

        return $verified
            ? LegacyVerdict::granted($algorithm)
            : LegacyVerdict::refused($algorithm, LegacyRefusal::WrongPassword);
    }

    /**
     * The ONLY hash comparison in this plugin.
     *
     * `$computed` is nullable because several algorithm classes return null
     * for an input they cannot process.
     *
     * The `=== ''` half of the guard is UNREACHABLE today, which a revert
     * check established — removing it passes the whole suite, because CHECK 1
     * refuses an empty stored value and no algorithm class returns an empty
     * string (each returns null instead). It is kept for the same reason as
     * the `*0` guard above: `hash_equals('', '')` is TRUE, so the one way this
     * could go wrong is a total authentication bypass.
     *
     * `hash_equals` AND NOT `===`, AND THAT CANNOT BE PINNED BY A TEST.
     * Replacing it with `===` passes the entire suite, because the two agree
     * on every input and differ only in TIMING — which no unit test can
     * observe. It is stated here rather than left to be rediscovered: the
     * reason for `hash_equals` is that `===` leaks the length of the matching
     * prefix, and for the bare digest family, where an attacker can make
     * millions of attempts a second against a local copy, that leak is real.
     */
    private function matches(?string $computed, string $stored): bool
    {
        if ($computed === null || $computed === '') {
            return false;
        }

        return hash_equals($stored, $computed);
    }

    private function checkCrypt(#[\SensitiveParameter] string $password, string $stored): bool
    {
        // crypt() uses the stored hash as its own setting string, so this
        // recomputes with the original salt and rounds.
        $computed = crypt($password, $stored);

        // UNREACHABLE TODAY, AND KEPT ANYWAY. A revert check established that:
        // removing this passes the whole suite.
        //
        // The reason is that CHECK 3 already refuses a stored `*0` — the
        // `*0`-against-`*0` case this was written to stop never arrives here,
        // so an earlier version of this comment credited the guard with a
        // protection that `HashDetector::isCryptFormed()` actually provides.
        // Probed directly as well: PHP's `crypt()` did not return `*0` for any
        // stored value that passes CHECK 3, including salts containing `:`,
        // `*`, a newline and high bytes.
        //
        // It stays because of what it guards against rather than how likely
        // that is. If `*0` ever did reach here against a stored `*0`,
        // `hash_equals` would match and EVERY PASSWORD would authenticate for
        // that row. Three lines against a total authentication bypass is worth
        // paying for a branch no test can currently reach.
        if (\strlen($computed) < 13 || str_starts_with($computed, '*')) {
            return false;
        }

        return $this->matches($computed, $stored);
    }

    private function checkPbkdf2(#[\SensitiveParameter] string $password, string $stored): bool
    {
        $parsed = Pbkdf2Hash::parse($stored);

        // Unreachable: CHECK 3 already parsed it. Guarded anyway, because the
        // alternative to this `if` is a null dereference if the two checks
        // ever drift apart.
        if ($parsed === null) {
            return false;
        }

        // Raw bytes on both sides. Comparing the base64 forms would work too,
        // but decoding once and comparing bytes means the comparison is over
        // exactly the digest and not over an encoding of it.
        return $this->matches($parsed->recompute($password), $parsed->derived());
    }

    private function checkScrypt(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): bool {
        $parameters = $credential->parameters;

        if (!$parameters instanceof ScryptParameters) {
            return false;
        }

        $derived = Scrypt::derive($password, $parameters);

        // Encoded with the DECLARED encoding, then compared against the stored
        // string verbatim. Not sniffed — see ScryptParameters::$encoding.
        return $this->matches($parameters->encoding->encode($derived), $credential->stored());
    }

    private function checkFirebase(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): bool {
        $parameters = $credential->parameters;

        if (!$parameters instanceof FirebaseParameters) {
            return false;
        }

        return $this->matches(
            FirebaseScrypt::recompute($password, $parameters),
            $credential->stored(),
        );
    }

    private function checkDigest(
        #[\SensitiveParameter] string $password,
        LegacyCredential $credential,
    ): bool {
        $parameters = $credential->parameters;

        if (!$parameters instanceof DigestParameters) {
            return false;
        }

        // The length check that used to live here has MOVED to CHECK 3a in
        // decide(), because returning `false` from this method produced
        // WrongPassword — the exact verdict its own comment said it existed to
        // avoid. It now produces MalformedHash, which is what a truncated
        // column actually is. A revert check found it: removing the check from
        // here changed nothing observable, so the suite could not tell it
        // apart from dead code.
        return $this->matches($parameters->compute($password), $credential->stored());
    }

    /**
     * Whether a bare scheme's stored length agrees with its parameters.
     *
     * The bare schemes carry no self-describing shape, so this is the only
     * structural check available — and it is a real one, because for all three
     * the length is FULLY DETERMINED by the declared parameters:
     *
     *   digest    the algorithm's digest size, in the declared encoding
     *   scrypt    the declared output length, in the declared encoding
     *   firebase  the SIGNER KEY's length, base64'd — because the stored value
     *             is the signer key encrypted, and AES-CTR is a stream cipher,
     *             so the ciphertext is exactly as long as its plaintext
     *
     * A mismatch means a truncated column, or an algorithm, encoding or length
     * declared wrongly. Every one of those affects every row of that shape, so
     * it is an operational failure and not a wrong password.
     *
     * The self-describing schemes return true here: their shape was already
     * judged by CHECK 3, which is better at it.
     */
    private function storedLengthMatchesParameters(LegacyCredential $credential): bool
    {
        $stored     = $credential->stored();
        $parameters = $credential->parameters;

        if ($parameters instanceof DigestParameters) {
            return \strlen($stored) === $parameters->expectedLength();
        }

        if ($parameters instanceof ScryptParameters) {
            return \strlen($stored) === $parameters->encoding->lengthFor($parameters->length);
        }

        if ($parameters instanceof FirebaseParameters) {
            return \strlen($stored)
                === DigestEncoding::Base64->lengthFor(\strlen($parameters->signerKey));
        }

        // Plaintext has no length to predict — the stored value IS the
        // password, and a password may be any length. And the self-describing
        // schemes were judged by CHECK 3.
        return true;
    }

    /**
     * Whether the declared work factor is within the configured ceiling.
     *
     * The bare schemes are absent from this: their parameters are validated at
     * construction by their own value objects, which is the right place —
     * those come from the deployment's configuration rather than from a string
     * in an untrusted import file.
     */
    private function costIsAcceptable(LegacyCredential $credential): bool
    {
        $stored = $credential->stored();

        return match ($credential->algorithm) {
            LegacyAlgorithm::Bcrypt => $this->bcryptCost($stored) <= $this->config->maxBcryptCost,
            LegacyAlgorithm::Argon2 => $this->argon2Memory($stored) <= $this->config->maxArgon2MemoryKib,
            LegacyAlgorithm::Phpass
                => (Phpass::iterations($stored) ?? \PHP_INT_MAX) <= $this->config->maxIterations,
            LegacyAlgorithm::Pbkdf2
                => (Pbkdf2Hash::parse($stored)?->iterations ?? \PHP_INT_MAX)
                    <= $this->config->maxIterations,
            LegacyAlgorithm::Crypt  => $this->cryptRounds($stored) <= $this->config->maxIterations,
            LegacyAlgorithm::Scrypt, LegacyAlgorithm::FirebaseScrypt,
            LegacyAlgorithm::Digest, LegacyAlgorithm::Plaintext => true,
        };
    }

    private function bcryptCost(string $stored): int
    {
        $options = password_get_info($stored)['options'] ?? [];

        // PHP_INT_MAX on an unreadable cost, so an unparseable hash is REFUSED
        // by the ceiling rather than waved through it.
        //
        // The fallback is UNREACHABLE today — a revert check showed that
        // returning 0 instead passes the whole suite — because CHECK 3 already
        // refuses any bcrypt hash `password_get_info()` cannot parse, and for
        // one it can parse the cost is always present. Kept because the
        // direction of the failure is the whole point: a ceiling that fails
        // OPEN on malformed input is decorative for exactly the input it
        // exists to stop.
        return isset($options['cost']) ? (int) $options['cost'] : \PHP_INT_MAX;
    }

    /**
     * The memory cost the HASH declares, parsed out of the PHC string.
     *
     * `password_get_info()` would do for a well-formed hash — it does read the
     * declared `m`. It is not used because it CANNOT FAIL: for a parameter
     * field that is absent or unparseable it silently substitutes PHP's own
     * defaults, so `m=zzz` reads as 65536 and passes any sane ceiling while
     * the hash's real cost is unknown. {@see Argon2Hash} returns null there,
     * and null becomes PHP_INT_MAX below, so the ceiling refuses it.
     *
     * TODAY THE TWO ARE EQUIVALENT, and a revert check proved it: swapping
     * this for `password_get_info()` passes the whole suite. The reason is the
     * check ORDERING — CHECK 3 uses this same parser, so any hash reaching the
     * ceiling has already parsed, and for a hash that parses the two sources
     * agree. Probed across six parameter sets including an integer-overflowing
     * `m=99999999999999999999`: identical every time.
     *
     * So this is not currently load-bearing, and it is kept because it stops
     * depending on another check's ordering for its correctness. Move CHECK 3
     * or change what it parses with, and the `password_get_info()` version
     * becomes wrong while this one stays right.
     */
    private function argon2Memory(string $stored): int
    {
        // PHP_INT_MAX on an unparseable hash, so it is REFUSED by the ceiling
        // rather than waved through it.
        return Argon2Hash::parse($stored)?->memoryCost ?? \PHP_INT_MAX;
    }

    /**
     * crypt(3)'s `rounds=` field, or the scheme's default when absent.
     *
     * sha256-crypt and sha512-crypt default to 5,000 rounds and md5-crypt has
     * a fixed 1,000, so an absent field is NOT unlimited — returning
     * PHP_INT_MAX for it would refuse every ordinary `$6$salt$hash`, which is
     * the overwhelming majority of them.
     */
    private function cryptRounds(string $stored): int
    {
        if (preg_match('/^\$[56]\$rounds=(\d+)\$/', $stored, $matches) === 1) {
            return (int) $matches[1];
        }

        return 5000;
    }

    /**
     * Log the outcome, when a logger is available.
     *
     * An operational refusal is an ERROR and not a warning, because every one
     * of them means a whole population of users cannot log in and nobody has
     * been told. A wrong password is logged at debug — it happens constantly
     * and is the application's business, not this plugin's.
     *
     * A SUCCESS is logged at info on purpose: during a migration, the count of
     * legacy verifications is the number that has to reach zero, and it is
     * unobtainable afterwards. The line carries the algorithm and no hash.
     */
    private function record(LegacyVerdict $verdict): void
    {
        if ($this->logger === null) {
            return;
        }

        if ($verdict->verified) {
            $this->logger->info($verdict->logLine());

            return;
        }

        if ($verdict->suggestsMisconfiguration()) {
            $this->logger->error($verdict->logLine());

            return;
        }

        $this->logger->debug($verdict->logLine());
    }
}

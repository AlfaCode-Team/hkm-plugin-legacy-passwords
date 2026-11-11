<?php

declare(strict_types=1);

namespace Plugins\LegacyPasswords\Domain\Algorithms;

use Plugins\LegacyPasswords\Domain\FirebaseParameters;

/**
 * Firebase Authentication's modified scrypt.
 *
 * ════════════════════════════════════════════════════════════════════════════
 * THE CONSTRUCTION
 * ════════════════════════════════════════════════════════════════════════════
 *
 *     derived = scrypt(password, salt ‖ saltSeparator,
 *                      N = 2^mem_cost, r = rounds, p = 1, dkLen = 64)
 *     stored  = base64( AES-256-CTR(key = derived[0..31],
 *                                   iv  = sixteen zero bytes,
 *                                   plaintext = signerKey) )
 *
 * It is "modified scrypt" only in the sense that scrypt's output is not the
 * answer — it is an AES KEY, and the answer is the project's signer key
 * encrypted under it. The password is therefore never compared to a digest of
 * itself; it is compared to a ciphertext that only the right password can
 * produce.
 *
 * That has one real consequence: the signer key is a per-project SECRET, and
 * an export without it cannot be verified by anybody, which is the point. It
 * also means the stored value's length is the SIGNER KEY's length, not a
 * digest length — Firebase's default 64-byte signer key gives 88 characters of
 * base64, and a project with a 32-byte one gives 44.
 *
 * A fixed zero IV with a fixed plaintext would be a grave mistake in an
 * encryption scheme, since identical keys would give identical ciphertext.
 * Here that determinism is the requirement, and the key is different for every
 * password.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * THIS IS CHECKED AGAINST AN INDEPENDENT IMPLEMENTATION
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The tests carry three known-answer vectors whose expected values were
 * produced by Node — `crypto.scryptSync` for the derivation and
 * `crypto.createCipheriv('aes-256-ctr', …)` for the encryption — so neither
 * half of the construction is checked only against itself. One of the three
 * uses the salt/separator/signer-key triple from Firebase's own published
 * example.
 *
 * What has NOT happened is a real Firebase export being imported. The
 * construction is pinned, but no live project's hashes have been verified
 * against it, and the README says so rather than implying otherwise.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * COST
 * ────────────────────────────────────────────────────────────────────────────
 *
 * The scrypt step at Firebase's defaults is MEASURED at about 1.55 s in this
 * pure-PHP implementation. See {@see Scrypt} — the asymmetry that makes that
 * acceptable (one verification per user, ever) is explained there.
 */
final class FirebaseScrypt
{
    private const CIPHER = 'aes-256-ctr';

    /** Sixteen zero bytes. Deterministic by design — see the class docblock. */
    private const IV = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /**
     * Recompute the stored hash, base64-encoded as the export writes it.
     *
     * Returns null when the AES step fails, which on a build with OpenSSL
     * should not happen — but `openssl_encrypt()` returns false rather than
     * throwing, and treating false as an empty string would compare `''`
     * against the stored hash and call it a wrong password. A null here is
     * reported as an operational failure instead.
     *
     * The comparison is NOT done here. See {@see Phpass::recompute()} for why
     * there is exactly one `hash_equals` in this plugin.
     */
    public static function recompute(
        #[\SensitiveParameter] string $password,
        FirebaseParameters $parameters,
    ): ?string {
        $derived = Scrypt::derive($password, $parameters->scrypt());

        // AES-256 takes a 32-byte key; the derivation produces 64 and the
        // upper half is discarded. Taking the WRONG half, or all 64, makes
        // openssl_encrypt() emit a warning and truncate — which would still
        // return a plausible ciphertext of the right length.
        $key = substr($derived, 0, FirebaseParameters::AES_KEY_LENGTH);

        if (\strlen($key) !== FirebaseParameters::AES_KEY_LENGTH) {
            return null;
        }

        $ciphertext = openssl_encrypt(
            $parameters->signerKey,
            self::CIPHER,
            $key,
            \OPENSSL_RAW_DATA,
            self::IV,
        );

        if ($ciphertext === false || $ciphertext === '') {
            return null;
        }

        return base64_encode($ciphertext);
    }
}

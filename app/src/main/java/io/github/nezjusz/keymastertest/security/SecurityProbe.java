package io.github.nezjusz.keymastertest.security;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import java.lang.reflect.Method;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Collects the device-trust signals this app can actually observe, and derives an overall
 * assessment from them.
 *
 * <p>Everything here is best-effort. A signal the platform will not disclose is reported as
 * unavailable rather than guessed, because a diagnostic that fills in blanks with optimism is
 * worse than one that admits ignorance.
 */
public final class SecurityProbe {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String ATTESTATION_ALIAS = "KeymasterTestAttestationKey";

    /** keymaster.h: KM_ERROR_KEYMASTER_NOT_CONFIGURED. */
    private static final int KM_ERROR_KEYMASTER_NOT_CONFIGURED = -10003;

    private SecurityProbe() {
    }

    public static SecurityReport run(boolean keystoreHardwareBacked, boolean keystoreBackingUnknown) {
        List<SecurityReport.Signal> signals = new ArrayList<>();
        List<String> reasons = new ArrayList<>();

        Attestation attestation = null;
        String attestationNote = null;
        boolean attestationFailed = false;
        StringBuilder detail = new StringBuilder();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            attestationNote = "Requires Android 7.0";
            attestationFailed = false;
        } else {
            try {
                Attempt attempt = runAttestation();
                attestation = attempt.attestation;
                attestationNote = attempt.note;
                if (attestation == null) {
                    attestationNote = "Not attested";
                }
            } catch (Exception e) {
                detail.append(diagnose(e)).append("\n\n").append(describeFull(e));
                attestationFailed = true;
            }
        }

        // Key attestation
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            signals.add(signal("Key attestation", SecurityReport.Status.UNKNOWN, attestationNote));
        } else if (attestation == null) {
            SecurityReport.Status status = attestationFailed
                    ? SecurityReport.Status.BAD
                    : SecurityReport.Status.UNKNOWN;
            signals.add(signal("Key attestation", status,
                    attestationFailed ? "Failed" : "Unavailable"));
            if (attestationFailed) {
                // Short title here; the diagnosis and the exception chain live in the detail.
                reasons.add("Key attestation failed");
            }
        } else {
            signals.add(signal("Key attestation", SecurityReport.Status.GOOD, "Certificate chain valid"));
            if (attestationNote != null) {
                appendDetail(detail, attestationNote);
            }
        }

        // Attestation security level
        if (attestation != null && attestation.attestationSecurityLevel != null) {
            int level = attestation.attestationSecurityLevel;
            SecurityReport.Status status;
            if (level == Attestation.LEVEL_STRONGBOX) {
                status = SecurityReport.Status.GOOD;
            } else if (level == Attestation.LEVEL_TRUSTED_ENVIRONMENT) {
                status = SecurityReport.Status.GOOD;
            } else {
                status = SecurityReport.Status.WARNING;
                reasons.add("Keys are attested at the software level, not in a secure element");
            }
            signals.add(signal("Attestation level", status,
                    Attestation.securityLevelName(level)));
        } else {
            signals.add(signal("Attestation level", SecurityReport.Status.UNKNOWN, "No attestation"));
        }

        // Device lock state, from the attestation record when available
        if (attestation != null && attestation.deviceLocked != null) {
            boolean locked = attestation.deviceLocked;
            signals.add(signal("Device locked", locked
                            ? SecurityReport.Status.GOOD
                            : SecurityReport.Status.WARNING,
                    locked ? "Yes" : "No"));
            if (!locked) {
                reasons.add("Device is not locked, so keys are not encrypted at rest");
            }
        } else {
            signals.add(signal("Device locked", SecurityReport.Status.UNKNOWN, "Not reported"));
        }

        // Verified boot
        String bootState = SystemProperties.get("ro.boot.verifiedbootstate");
        if (bootState == null) {
            signals.add(signal("Verified boot", SecurityReport.Status.UNKNOWN, "Unavailable"));
        } else if ("green".equalsIgnoreCase(bootState)) {
            signals.add(signal("Verified boot", SecurityReport.Status.GOOD, "Verified"));
        } else if ("yellow".equalsIgnoreCase(bootState)) {
            signals.add(signal("Verified boot", SecurityReport.Status.WARNING, "Warning (yellow)"));
            reasons.add("Verified boot is yellow; the platform is signed with a test key");
        } else {
            signals.add(signal("Verified boot", SecurityReport.Status.BAD, "Failed (" + bootState + ")"));
            reasons.add("Verified boot state is " + bootState);
        }

        // Bootloader
        String flashLocked = SystemProperties.get("ro.boot.flash.locked");
        String deviceState = SystemProperties.get("ro.boot.vbmeta.device_state");
        String tags = SystemProperties.get("ro.build.tags");
        Boolean locked = readBootloader(flashLocked, deviceState, tags);
        if (locked == null) {
            signals.add(signal("Bootloader", SecurityReport.Status.UNKNOWN, "Unavailable"));
        } else if (locked) {
            signals.add(signal("Bootloader", SecurityReport.Status.GOOD, "Locked"));
        } else {
            signals.add(signal("Bootloader", SecurityReport.Status.BAD, "Unlocked"));
            reasons.add("Bootloader is unlocked, so the boot chain can be modified");
        }

        // Device integrity, derived from what we could read.
        signals.add(deriveIntegrity(signals, reasons, attestation != null));

        SecurityReport.Trust trust = deriveTrust(signals, keystoreHardwareBacked,
                keystoreBackingUnknown, reasons);

        return new SecurityReport(signals, trust, headline(trust), explanation(trust), reasons,
                detail.length() == 0 ? null : detail.toString());
    }

    private static void appendDetail(StringBuilder detail, String text) {
        if (detail.length() > 0) {
            detail.append("\n\n");
        }
        detail.append(text);
    }

    private static Boolean readBootloader(String flashLocked, String deviceState, String tags) {
        if (flashLocked != null) {
            return "1".equals(flashLocked.trim());
        }
        if (deviceState != null) {
            return "locked".equalsIgnoreCase(deviceState.trim());
        }
        if (tags != null) {
            if (tags.contains("test-keys") || tags.contains("dev-keys")) {
                return Boolean.FALSE;
            }
            if (tags.contains("verified-boot")) {
                return Boolean.TRUE;
            }
        }
        return null;
    }

    private static SecurityReport.Signal deriveIntegrity(List<SecurityReport.Signal> signals,
                                                          List<String> reasons,
                                                          boolean attested) {
        SecurityReport.Status worst = SecurityReport.Status.GOOD;
        boolean anyKnown = false;

        for (SecurityReport.Signal signal : signals) {
            if (signal.status == SecurityReport.Status.UNKNOWN) {
                continue;
            }
            anyKnown = true;
            if (signal.status == SecurityReport.Status.BAD) {
                return new SecurityReport.Signal("Device integrity",
                        SecurityReport.Status.BAD, "Not verified");
            }
            if (signal.status == SecurityReport.Status.WARNING) {
                worst = SecurityReport.Status.WARNING;
            }
        }

        if (!anyKnown) {
            return new SecurityReport.Signal("Device integrity",
                    SecurityReport.Status.UNKNOWN, "Unknown");
        }
        if (worst == SecurityReport.Status.WARNING) {
            return new SecurityReport.Signal("Device integrity",
                    SecurityReport.Status.WARNING, "Partially verified");
        }
        return new SecurityReport.Signal("Device integrity",
                SecurityReport.Status.GOOD,
                attested ? "Verified" : "Boot state verified");
    }

    private static SecurityReport.Trust deriveTrust(List<SecurityReport.Signal> signals,
                                                   boolean keystoreHardwareBacked,
                                                   boolean keystoreBackingUnknown,
                                                   List<String> reasons) {
        boolean anyBad = false;
        boolean anyGood = false;
        int unknown = 0;

        for (SecurityReport.Signal signal : signals) {
            switch (signal.status) {
                case BAD:
                    anyBad = true;
                    break;
                case GOOD:
                    anyGood = true;
                    break;
                default:
                    unknown++;
                    break;
            }
        }

        if (!keystoreHardwareBacked && !keystoreBackingUnknown) {
            anyBad = true;
            reasons.add("Keystore keys are not hardware backed");
        }

        if (anyBad) {
            return SecurityReport.Trust.COMPROMISED;
        }
        if (keystoreBackingUnknown) {
            return SecurityReport.Trust.UNDETERMINED;
        }
        if (anyGood && unknown == 0) {
            return SecurityReport.Trust.STRONG;
        }
        if (anyGood) {
            return SecurityReport.Trust.PARTIAL;
        }
        return SecurityReport.Trust.UNDETERMINED;
    }

    private static String headline(SecurityReport.Trust trust) {
        switch (trust) {
            case STRONG:
                return "Signals are strong";
            case PARTIAL:
                return "Signals are incomplete";
            case COMPROMISED:
                return "Conclusive problems found";
            default:
                return "Not enough information";
        }
    }

    private static String explanation(SecurityReport.Trust trust) {
        switch (trust) {
            case STRONG:
                return "The Keystore is hardware backed and every signal this app could read "
                        + "was healthy. This is still not a guarantee; it reflects only the "
                        + "signals listed above.";
            case PARTIAL:
                return "Nothing conclusive failed, but some signals could not be read. Treat "
                        + "this as encouraging rather than proven.";
            case COMPROMISED:
                return "At least one signal is conclusively bad. See the reasons below.";
            default:
                return "The platform would not disclose enough to assess this device.";
        }
    }

    private static SecurityReport.Signal signal(String label, SecurityReport.Status status, String value) {
        return new SecurityReport.Signal(label, status, value);
    }

    /**
     * Generates a throwaway key carrying a challenge, then reads the attestation certificate
     * chain the Keystore produced for it.
     *
     * <p>{@code PURPOSE_ATTEST_KEY} is the documented way to ask for an attestation, but several
     * shipping keymaster implementations reject the flag outright with
     * {@code IllegalArgumentException: Unknown purpose: 128}. Those devices still attest ordinary
     * signing keys, so the probe retries with a plain signing key rather than reporting a
     * capability the device does have as missing.
     *
     * @return the parsed attestation (null if the Keystore declined to attest) plus any caveat
     */
    @RequiresApi(Build.VERSION_CODES.N)
    private static Attempt runAttestation() throws Exception {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        deleteIfPresent(keyStore);

        try {
            Exception firstFailure;
            try {
                return new Attempt(attest(keyStore, challenge,
                        KeyProperties.PURPOSE_ATTEST_KEY | KeyProperties.PURPOSE_SIGN), null);
            } catch (Exception e) {
                firstFailure = e;
            }

            deleteIfPresent(keyStore);
            try {
                Attestation attestation = attest(keyStore, challenge,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
                return new Attempt(attestation,
                        "This device rejected the dedicated attestation purpose, so the chain "
                                + "came from an ordinary signing key");
            } catch (Exception retryFailure) {
                throw new IllegalStateException(
                        "The device rejected the dedicated attestation purpose ("
                                + describeFull(firstFailure) + ") and attesting a plain signing "
                                + "key failed as well: " + describeFull(retryFailure),
                        retryFailure);
            }
        } finally {
            deleteIfPresent(keyStore);
        }
    }

    @RequiresApi(Build.VERSION_CODES.N)
    private static Attestation attest(KeyStore keyStore, byte[] challenge, int purposes)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE);
        generator.initialize(new KeyGenParameterSpec.Builder(ATTESTATION_ALIAS, purposes)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setKeySize(2048)
                .setAttestationChallenge(challenge)
                .build());

        generator.generateKeyPair();

        Certificate[] chain = keyStore.getCertificateChain(ATTESTATION_ALIAS);
        if (chain == null || chain.length < 2) {
            throw new IllegalStateException(
                    "Keystore produced no attestation chain; the device is most likely not "
                            + "locked with a secure screen lock");
        }

        Attestation attestation = Attestation.fromChain(chain);
        if (attestation == null) {
            throw new IllegalStateException("Certificate chain carries no attestation extension");
        }
        if (!attestation.challengeMatches(challenge)) {
            throw new IllegalStateException("Attestation challenge did not match");
        }
        return attestation;
    }

    private static final class Attempt {
        final Attestation attestation;
        final String note;

        Attempt(Attestation attestation, String note) {
            this.attestation = attestation;
            this.note = note;
        }
    }

    private static void deleteIfPresent(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(ATTESTATION_ALIAS)) {
                keyStore.deleteEntry(ATTESTATION_ALIAS);
            }
        } catch (Exception ignored) {
        }
    }

    /**
     * Turns an exception chain into one short, human-meaningful sentence.
     *
     * <p>The Keystore stacks a generic provider error on top of the keymaster status that
     * actually explains what went wrong, so the most specific known code wins rather than the
     * outermost exception. The full chain is still available for the expandable details.
     */
    private static String diagnose(Throwable t) {
        for (Throwable cause = t; cause != null; cause = cause.getCause()) {
            int code = keymasterCode(cause);
            if (code == 0) {
                continue;
            }
            if (code == KM_ERROR_KEYMASTER_NOT_CONFIGURED) {
                return "the TEE attestation keybox is not provisioned (Keymaster error "
                        + KM_ERROR_KEYMASTER_NOT_CONFIGURED + "), so this device cannot attest "
                        + "its own hardware keys";
            }
            return "the Keystore reported Keymaster error " + code;
        }
        String message = t.getMessage();
        if (message == null || message.isEmpty()) {
            return t.getClass().getSimpleName();
        }
        return message.length() > 90 ? message.substring(0, 87) + "..." : message;
    }

    /**
     * Extracts the keymaster status from an exception in the chain.
     *
     * <p>Android raises {@code android.security.KeyStoreException}, which is hidden from the
     * public SDK and is not a {@code java.security.KeyStoreException}, so it cannot be named or
     * type-checked here. Its message is the bare status, which is what the check keys off.
     */
    private static int keymasterCode(Throwable t) {
        if (!t.getClass().getSimpleName().endsWith("KeyStoreException")) {
            return 0;
        }
        String message = t.getMessage();
        if (message == null) {
            return 0;
        }
        try {
            return Integer.parseInt(message.trim());
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static String describeFull(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (int depth = 0; t != null && depth < 4; depth++, t = t.getCause()) {
            if (depth > 0) {
                sb.append("\n  caused by ");
            }
            sb.append(t.getClass().getSimpleName());
            String message = t.getMessage();
            if (message != null && !message.isEmpty()) {
                sb.append(": ").append(message);
            }
        }
        return sb.toString();
    }

    /** Reflective access to system properties, which the platform restricts to greylisted apps. */
    static final class SystemProperties {

        private static Method getter;
        private static boolean resolved;

        private SystemProperties() {
        }

        static String get(String key) {
            try {
                if (!resolved) {
                    Class<?> type = Class.forName("android.os.SystemProperties");
                    getter = type.getMethod("get", String.class);
                    resolved = true;
                }
                if (getter == null) {
                    return null;
                }
                Object value = getter.invoke(null, key);
                if (value instanceof String && !((String) value).isEmpty()) {
                    return (String) value;
                }
            } catch (Throwable ignored) {
                resolved = true;
                getter = null;
            }
            return null;
        }
    }
}

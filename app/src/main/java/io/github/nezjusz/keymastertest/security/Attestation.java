package io.github.nezjusz.keymastertest.security;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * The Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
 *
 * <pre>
 * KeyDescription ::= SEQUENCE {
 *     attestationVersion       INTEGER,
 *     attestationSecurityLevel ENUMERATED,  -- Software=0, TrustedEnvironment=1, StrongBox=2
 *     keymasterVersion         INTEGER,
 *     keymasterSecurityLevel   ENUMERATED,
 *     attestationChallenge     OCTET_STRING,
 *     uniqueId                 OCTET_STRING,
 *     softwareEnforced         AuthorizationList,
 *     teeEnforced              AuthorizationList,
 * }
 * </pre>
 *
 * Only the fields this app reports are decoded. Anything absent stays null rather than
 * defaulting, so "the device did not say" is never confused with a value.
 */
public final class Attestation {

    public static final String OID = "1.3.6.1.4.1.11129.2.1.17";

    public static final int LEVEL_SOFTWARE = 0;
    public static final int LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int LEVEL_STRONGBOX = 2;

    public static final int BOOT_VERIFIED = 0;
    public static final int BOOT_SELF_SIGNED = 1;
    public static final int BOOT_UNVERIFIED = 2;
    public static final int BOOT_FAILED = 3;

    // AuthorizationList tag numbers. These exceed 30, so they arrive in high-tag-number form.
    private static final int TAG_ROOT_OF_TRUST = 704;
    private static final int TAG_DEVICE_LOCKED = 720;
    private static final int TAG_VERIFIED_BOOT_STATE = 900;
    private static final int TAG_VERIFIED_BOOT_HASH = 901;

    public final Integer attestationVersion;
    public final Integer attestationSecurityLevel;
    public final Integer keymasterVersion;
    public final Integer keymasterSecurityLevel;
    public final byte[] challenge;
    public final byte[] uniqueId;

    /** From softwareEnforced, tag 720. */
    public final Boolean deviceLocked;
    /** From softwareEnforced, tag 900. */
    public final Integer verifiedBootState;
    /** From softwareEnforced, tag 901. */
    public final byte[] verifiedBootHash;

    private Attestation(Integer attestationVersion, Integer attestationSecurityLevel,
                        Integer keymasterVersion, Integer keymasterSecurityLevel,
                        byte[] challenge, byte[] uniqueId, Boolean deviceLocked,
                        Integer verifiedBootState, byte[] verifiedBootHash) {
        this.attestationVersion = attestationVersion;
        this.attestationSecurityLevel = attestationSecurityLevel;
        this.keymasterVersion = keymasterVersion;
        this.keymasterSecurityLevel = keymasterSecurityLevel;
        this.challenge = challenge;
        this.uniqueId = uniqueId;
        this.deviceLocked = deviceLocked;
        this.verifiedBootState = verifiedBootState;
        this.verifiedBootHash = verifiedBootHash;
    }

    public boolean challengeMatches(byte[] expected) {
        return Arrays.equals(challenge, expected);
    }

    public static String securityLevelName(Integer level) {
        if (level == null) {
            return "unknown";
        }
        switch (level) {
            case LEVEL_SOFTWARE:
                return "Software";
            case LEVEL_TRUSTED_ENVIRONMENT:
                return "Trusted Environment (TEE)";
            case LEVEL_STRONGBOX:
                return "StrongBox";
            default:
                return "unknown (" + level + ")";
        }
    }

    public static String bootStateName(Integer state) {
        if (state == null) {
            return "unknown";
        }
        switch (state) {
            case BOOT_VERIFIED:
                return "verified";
            case BOOT_SELF_SIGNED:
                return "self-signed";
            case BOOT_UNVERIFIED:
                return "unverified";
            case BOOT_FAILED:
                return "failed";
            default:
                return "unknown (" + state + ")";
        }
    }

    /**
     * Extracts and parses the attestation record from a certificate chain.
     *
     * @return the attestation, or null if the chain carries no attestation certificate
     */
    public static Attestation fromChain(Certificate[] chain) throws Exception {
        if (chain == null || chain.length == 0) {
            return null;
        }
        for (Certificate certificate : chain) {
            if (!(certificate instanceof X509Certificate)) {
                continue;
            }
            X509Certificate x509 = (X509Certificate) certificate;
            byte[] wrapped = x509.getExtensionValue(OID);
            if (wrapped == null) {
                continue;
            }
            // getExtensionValue returns a DER OCTET STRING wrapping the real extension value.
            byte[] extension = new Der(wrapped).next().value();
            return parse(extension);
        }
        return null;
    }

    static Attestation parse(byte[] extension) {
        Der fields = new Der(extension).next().content();

        Integer version = null;
        Integer attestationLevel = null;
        Integer keymasterVersion = null;
        Integer keymasterLevel = null;
        byte[] challenge = null;
        byte[] uniqueId = null;
        AuthorizationValues values = null;

        while (fields.hasMore()) {
            Der.Tlv tlv = fields.next();
            switch (tlv.tagNumber) {
                case Der.TAG_INTEGER:
                    if (version == null) {
                        version = tlv.asInt();
                    } else if (keymasterVersion == null) {
                        keymasterVersion = tlv.asInt();
                    }
                    break;
                case Der.TAG_ENUMERATED:
                    if (attestationLevel == null) {
                        attestationLevel = tlv.asInt();
                    } else if (keymasterLevel == null) {
                        keymasterLevel = tlv.asInt();
                    }
                    break;
                case Der.TAG_OCTET_STRING:
                    if (challenge == null) {
                        challenge = tlv.value();
                    } else {
                        uniqueId = tlv.value();
                    }
                    break;
                case Der.TAG_SEQUENCE:
                    // First SEQUENCE is softwareEnforced, second is teeEnforced.
                    if (values == null) {
                        values = AuthorizationValues.from(tlv.content());
                    }
                    break;
                default:
                    break;
            }
        }

        return new Attestation(version, attestationLevel, keymasterVersion, keymasterLevel,
                challenge, uniqueId,
                values == null ? null : values.deviceLocked,
                values == null ? null : values.verifiedBootState,
                values == null ? null : values.verifiedBootHash);
    }

    /** Decoded from a single AuthorizationList. */
    private static final class AuthorizationValues {
        final Boolean deviceLocked;
        final Integer verifiedBootState;
        final byte[] verifiedBootHash;

        private AuthorizationValues(Boolean deviceLocked, Integer verifiedBootState,
                                   byte[] verifiedBootHash) {
            this.deviceLocked = deviceLocked;
            this.verifiedBootState = verifiedBootState;
            this.verifiedBootHash = verifiedBootHash;
        }

        static AuthorizationValues from(Der list) {
            Boolean deviceLocked = null;
            Integer verifiedBootState = null;
            byte[] verifiedBootHash = null;

            while (list.hasMore()) {
                Der.Tlv tlv = list.next();
                switch (tlv.tagNumber) {
                    case TAG_DEVICE_LOCKED:
                        // Explicitly tagged, so the boolean is wrapped in another TLV.
                        deviceLocked = unwrapBoolean(tlv);
                        break;
                    case TAG_VERIFIED_BOOT_STATE:
                        verifiedBootState = unwrapInt(tlv);
                        break;
                    case TAG_VERIFIED_BOOT_HASH:
                        verifiedBootHash = unwrapOctetString(tlv);
                        break;
                    case TAG_ROOT_OF_TRUST:
                        // Older devices report the same values inside RootOfTrust (704).
                        // [704] is EXPLICIT, so its value is a complete RootOfTrust SEQUENCE.
                        Der wrapped = new Der(tlv.value());
                        Der root = wrapped.hasMore() ? wrapped.next().content() : wrapped;
                        if (root.hasMore()) {
                            root.next(); // verifiedBootKey
                        }
                        if (root.hasMore()) {
                            deviceLocked = root.next().asBoolean();
                        }
                        if (root.hasMore()) {
                            Der.Tlv state = root.next();
                            verifiedBootState = state.tagNumber == Der.TAG_ENUMERATED
                                    ? state.asInt()
                                    : new Der(state.value()).next().asInt();
                        }
                        if (root.hasMore()) {
                            verifiedBootHash = root.next().value();
                        }
                        break;
                    default:
                        break;
                }
            }
            return new AuthorizationValues(deviceLocked, verifiedBootState, verifiedBootHash);
        }

        /** These AuthorizationList entries are EXPLICIT, so the value is wrapped once more. */
        private static Integer unwrapInt(Der.Tlv tlv) {
            return new Der(tlv.value()).next().asInt();
        }

        private static Boolean unwrapBoolean(Der.Tlv tlv) {
            return new Der(tlv.value()).next().asBoolean();
        }

        private static byte[] unwrapOctetString(Der.Tlv tlv) {
            return new Der(tlv.value()).next().value();
        }
    }
}

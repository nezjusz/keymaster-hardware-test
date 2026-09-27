package io.github.nezjusz.keymastertest.security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Exercises the attestation extension parser against hand-built DER.
 *
 * <p>The device used for development is not locked with a secure screen lock, so the Keystore
 * never produces a real attestation certificate chain there. Building the structure by hand is
 * the only way to check the tag decoding, the high-tag-number form, and the EXPLICIT unwrapping
 * that the real extension depends on.
 */
public class AttestationParserTest {

    private static final int CONTEXT_SPECIFIC = 0x80;

    @Test
    public void parsesFullExtension() {
        byte[] challenge = new byte[32];
        for (int i = 0; i < challenge.length; i++) {
            challenge[i] = (byte) i;
        }
        byte[] uniqueId = {0x0A, 0x0B, 0x0C, 0x0D};
        byte[] bootHash = new byte[32];
        for (int i = 0; i < bootHash.length; i++) {
            bootHash[i] = (byte) (0xFF - i);
        }

        byte[] softwareEnforced = sequence(
                explicit(720, tlv(0x01, new byte[]{(byte) 0xFF})),
                explicit(900, tlv(0x0A, new byte[]{0x00})),
                explicit(901, tlv(0x04, bootHash)));
        byte[] teeEnforced = sequence();

        byte[] extension = sequence(
                tlv(0x02, new byte[]{0x03}),                    // attestationVersion
                tlv(0x0A, new byte[]{0x01}),                    // attestationSecurityLevel: TEE
                tlv(0x02, new byte[]{0x04}),                    // keymasterVersion
                tlv(0x0A, new byte[]{0x01}),                    // keymasterSecurityLevel: TEE
                tlv(0x04, challenge),                           // attestationChallenge
                tlv(0x04, uniqueId),                            // uniqueId
                softwareEnforced,                    // softwareEnforced
                teeEnforced);                        // teeEnforced

        Attestation result = Attestation.parse(extension);

        assertNotNull(result);
        assertEquals(Integer.valueOf(3), result.attestationVersion);
        assertEquals(Integer.valueOf(Attestation.LEVEL_TRUSTED_ENVIRONMENT),
                result.attestationSecurityLevel);
        assertEquals(Integer.valueOf(4), result.keymasterVersion);
        assertEquals(Integer.valueOf(Attestation.LEVEL_TRUSTED_ENVIRONMENT),
                result.keymasterSecurityLevel);
        assertArrayEquals(challenge, result.challenge);
        assertTrue(result.challengeMatches(challenge));
        assertArrayEquals(uniqueId, result.uniqueId);
        assertEquals(Boolean.TRUE, result.deviceLocked);
        assertEquals(Integer.valueOf(Attestation.BOOT_VERIFIED), result.verifiedBootState);
        assertArrayEquals(bootHash, result.verifiedBootHash);
    }

    @Test
    public void parsesRootOfTrustFallback() {
        // Older devices report these inside RootOfTrust (704) rather than at the top level.
        byte[] bootHash = {0x11, 0x22, 0x33, 0x44};
        byte[] rootOfTrust = sequence(
                tlv(0x04, new byte[]{0x01, 0x02}),      // verifiedBootKey
                tlv(0x01, new byte[]{0x00}),            // deviceLocked: false
                tlv(0x0A, new byte[]{0x02}),            // verifiedBootState: unverified
                tlv(0x04, bootHash));                    // verifiedBootHash

        byte[] softwareEnforced = sequence(explicit(704, rootOfTrust));
        byte[] extension = sequence(
                tlv(0x02, new byte[]{0x03}),
                tlv(0x0A, new byte[]{0x01}),
                tlv(0x02, new byte[]{0x04}),
                tlv(0x0A, new byte[]{0x01}),
                tlv(0x04, new byte[32]),
                tlv(0x04, new byte[]{0x00}),
                softwareEnforced,
                sequence());

        Attestation result = Attestation.parse(extension);

        assertNotNull(result);
        assertEquals(Boolean.FALSE, result.deviceLocked);
        assertEquals(Integer.valueOf(Attestation.BOOT_UNVERIFIED), result.verifiedBootState);
        assertArrayEquals(bootHash, result.verifiedBootHash);
    }

    @Test
    public void leavesAbsentFieldsNullRatherThanDefaulting() {
        byte[] extension = sequence(
                tlv(0x02, new byte[]{0x03}),
                tlv(0x0A, new byte[]{0x00}),
                tlv(0x02, new byte[]{0x04}),
                tlv(0x0A, new byte[]{0x00}),
                tlv(0x04, new byte[]{0x05, 0x06}),
                tlv(0x04, new byte[]{0x00}),
                sequence(),
                sequence());

        Attestation result = Attestation.parse(extension);

        assertNotNull(result);
        assertNull("deviceLocked must stay null when not reported", result.deviceLocked);
        assertNull("verifiedBootState must stay null when not reported", result.verifiedBootState);
        assertNull(result.verifiedBootHash);
        assertEquals(Integer.valueOf(Attestation.LEVEL_SOFTWARE), result.attestationSecurityLevel);
    }

    @Test
    public void rejectsTruncatedInput() {
        byte[] truncated = new byte[]{0x30, 0x40, 0x02, 0x01, 0x03};
        try {
            Attestation.parse(truncated);
            fail("expected a failure on a truncated extension");
        } catch (RuntimeException expected) {
            assertNotNull(expected);
        }
    }

    @Test
    public void encodesHighTagNumbersCorrectly() {
        // Guards the encoder the fixtures rely on: 720, 900 and 901 all exceed 30 and so must
        // use the high-tag-number form.
        assertArrayEquals(new byte[]{(byte) 0xBF, (byte) 0x85, (byte) 0x50},
                highTag(720));
        assertArrayEquals(new byte[]{(byte) 0xBF, (byte) 0x87, (byte) 0x04},
                highTag(900));
        assertArrayEquals(new byte[]{(byte) 0xBF, (byte) 0x87, (byte) 0x05},
                highTag(901));
    }

    // --- fixture construction helpers ---

    private static byte[] highTag(int tagNumber) {
        List<Integer> groups = new ArrayList<>();
        int value = tagNumber;
        groups.add(0, value & 0x7F);
        value >>>= 7;
        while (value > 0) {
            groups.add(0, value & 0x7F);
            value >>>= 7;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(CONTEXT_SPECIFIC | 0x20 | 0x1F);
        for (int i = 0; i < groups.size(); i++) {
            int group = groups.get(i);
            if (i < groups.size() - 1) {
                group |= 0x80;
            }
            out.write(group);
        }
        return out.toByteArray();
    }

    private static byte[] rawTlv(int identifier, byte[] value) {
        return rawTlvBytes(new byte[]{(byte) identifier}, value);
    }

    private static byte[] rawTlvBytes(byte[] identifier, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(identifier, 0, identifier.length);
        out.write(value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    private static byte[] tlv(int identifier, byte[] value) {
        return rawTlv(identifier, value);
    }

    private static byte[] explicit(int tagNumber, byte[] inner) {
        return rawTlvBytes(highTag(tagNumber), inner);
    }

    private static byte[] sequence(byte[]... elements) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] element : elements) {
            out.write(element, 0, element.length);
        }
        return rawTlv(0x30, out.toByteArray());
    }
}

package com.example.keymastertest;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.widget.FrameLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private static final String ALIAS = "KeymasterTestKey";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String[] SIGNATURE_ALGORITHMS = {
            "SHA256withRSA",
            "SHA256withRSAandMGF1",
    };
    private static final byte[] TEST_DATA =
            "keymaster hardware test".getBytes(StandardCharsets.UTF_8);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;
    private TextView output;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        output = new TextView(this);
        output.setTextSize(16);
        output.setPadding(48, 48, 48, 48);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextIsSelectable(true);
        output.setText("Testing Keymaster...");

        ScrollView scroll = new ScrollView(this);
        scroll.addView(output, new FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT));
        setContentView(scroll);

        executor.execute(this::runTest);
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        executor.shutdownNow();
        super.onDestroy();
    }

    private void runTest() {
        String report;
        try {
            report = probe();
        } catch (Exception e) {
            report = "KEYMASTER TEST\n\n\u274C TEST FAILED\n\n" + describe(e);
        }

        if (destroyed) {
            return;
        }
        final String text = report;
        runOnUiThread(() -> output.setText(text));
    }

    private String probe() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        deleteIfPresent(keyStore);

        String report;
        String cleanupFailure = null;
        try {
            report = generateReport();
        } finally {
            cleanupFailure = deleteIfPresent(keyStore);
        }
        return cleanupFailure == null ? report : report + "\n\n" + cleanupFailure;
    }

    private static String generateReport() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
        generator.initialize(new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .build());

        KeyPair pair = generator.generateKeyPair();

        KeyInfo info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE)
                .getKeySpec(pair.getPrivate(), KeyInfo.class);

        boolean roundTripOk;
        String roundTrip;
        try {
            roundTrip = "PASS (" + signAndVerify(pair) + ")";
            roundTripOk = true;
        } catch (Exception e) {
            roundTripOk = false;
            roundTrip = "FAIL - " + describe(e);
        }

        return report(info, roundTripOk, roundTrip);
    }

    private static String report(KeyInfo info, boolean roundTripOk, String roundTrip) {
        boolean hardwareBacked = isHardwareBacked(info);
        boolean insideSecureHardware = isInsideSecureHardware(info);

        String verdict;
        if (!roundTripOk) {
            verdict = "❌ KEYSTORE MALFUNCTIONING";
        } else if (hardwareBacked) {
            verdict = "✅ KEYSTORE REPORTS HARDWARE BACKING";
        } else {
            verdict = "❌ KEYSTORE REPORTS SOFTWARE KEYS";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("KEYMASTER TEST\n\n");
        sb.append(verdict).append("\n\n");
        sb.append("Sign/verify round trip: ").append(roundTrip).append('\n');
        sb.append("Security level: ").append(securityLevel(info)).append('\n');
        sb.append("Inside secure hardware: ").append(insideSecureHardware).append('\n');
        sb.append("Origin: ").append(originName(info.getOrigin())).append('\n');
        sb.append("Key size: ").append(info.getKeySize()).append(" bits\n");
        sb.append("Android: ").append(Build.VERSION.RELEASE)
                .append(" (API ").append(Build.VERSION.SDK_INT).append(')');

        if (hardwareBacked && !insideSecureHardware) {
            sb.append("\n\nNote: isInsideSecureHardware() is deprecated and known to report")
                    .append(" false on some builds. The security level above is the better signal.");
        }

        sb.append("\n\nA green verdict only means the Keystore works and reports hardware backing.")
                .append("\nIt does NOT verify that this device is properly provisioned. A device with")
                .append("\na blank or broken keybox passes this test. Only key attestation can")
                .append("\nprove the device's Root of Trust.");

        return sb.toString();
    }

    private static String signAndVerify(KeyPair pair) throws Exception {
        List<String> failures = new ArrayList<>();
        for (String algorithm : SIGNATURE_ALGORITHMS) {
            try {
                if (runSignature(algorithm, pair)) {
                    return algorithm;
                }
                failures.add(algorithm + " did not verify");
            } catch (Exception e) {
                String message = e.getMessage();
                failures.add(algorithm + ": "
                        + e.getClass().getSimpleName()
                        + (message == null || message.isEmpty() ? "" : " (" + message + ")"));
            }
        }

        StringBuilder sb = new StringBuilder("no usable padding -");
        for (String failure : failures) {
            sb.append("\n  ").append(failure);
        }
        throw new GeneralSecurityException(sb.toString());
    }

    private static boolean runSignature(String algorithm, KeyPair pair) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update(TEST_DATA);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(pair.getPublic());
        verifier.update(TEST_DATA);
        return verifier.verify(signature);
    }

    private static boolean isHardwareBacked(KeyInfo info) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                int level = info.getSecurityLevel();
                return level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                        || level == KeyProperties.SECURITY_LEVEL_STRONGBOX;
            }
            return isInsideSecureHardware(info);
        } catch (Exception e) {
            return false;
        }
    }

    @SuppressWarnings("deprecation")
    private static boolean isInsideSecureHardware(KeyInfo info) {
        try {
            return info.isInsideSecureHardware();
        } catch (Exception e) {
            return false;
        }
    }

    private static String securityLevel(KeyInfo info) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                        return "StrongBox";
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                        return "Trusted Environment (TEE)";
                    case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                        return "Software";
                    default:
                        return "Unknown";
                }
            }
            return isInsideSecureHardware(info) ? "Hardware (reported)" : "Software (reported)";
        } catch (Exception e) {
            return "Unavailable";
        }
    }

    private static String originName(int origin) {
        switch (origin) {
            case KeyProperties.ORIGIN_GENERATED:
                return "Generated";
            case KeyProperties.ORIGIN_IMPORTED:
                return "Imported";
            case KeyProperties.ORIGIN_SECURELY_IMPORTED:
                return "Securely imported";
            default:
                return "Unknown (" + origin + ")";
        }
    }

    /** Returns null on success, or a description of the failure. */
    private static String deleteIfPresent(KeyStore keyStore) {
        try {
            if (keyStore.containsAlias(ALIAS)) {
                keyStore.deleteEntry(ALIAS);
            }
            return null;
        } catch (Exception e) {
            return "Key cleanup: FAILED - " + describe(e);
        }
    }

    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (int depth = 0; t != null && depth < 8; depth++, t = t.getCause()) {
            if (depth > 0) {
                sb.append("\n\nCaused by: ");
            }
            sb.append(t.getClass().getName());
            String message = t.getMessage();
            sb.append(message == null || message.isEmpty() ? " (no message)" : "\n" + message);
        }
        return sb.toString();
    }
}

package io.github.nezjusz.keymastertest;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.DrawableRes;
import androidx.annotation.StringRes;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import com.google.android.material.bottomnavigation.BottomNavigationView;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.loadingindicator.LoadingIndicator;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends AppCompatActivity {

    private static final String ALIAS = "KeymasterTestKey";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final int KEY_SIZE_BITS = 2048;
    private static final String[] SIGNATURE_ALGORITHMS = {
            "SHA256withRSA",
            "SHA256withRSAandMGF1",
    };
    private static final byte[] TEST_DATA =
            "keymaster hardware test".getBytes(StandardCharsets.UTF_8);

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private volatile boolean destroyed;

    private View loading;
    private View resultTab;
    private View detailsTab;
    private MaterialCardView verdictCard;
    private ImageView verdictIcon;
    private TextView verdictView;
    private TextView detailsView;
    private TextView technicalView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        DynamicColors.applyToActivityIfAvailable(this);
        setContentView(R.layout.activity_main);

        loading = findViewById(R.id.loading);
        resultTab = findViewById(R.id.result_tab);
        detailsTab = findViewById(R.id.details_tab);
        verdictCard = findViewById(R.id.verdict_card);
        verdictIcon = findViewById(R.id.verdict_icon);
        verdictView = findViewById(R.id.verdict);
        detailsView = findViewById(R.id.details);
        technicalView = findViewById(R.id.technical);

        LoadingIndicator loadingIndicator = findViewById(R.id.loading_indicator);
        loadingIndicator.setIndicatorColor(
                ContextCompat.getColor(this, R.color.indicator_primary),
                ContextCompat.getColor(this, R.color.indicator_secondary),
                ContextCompat.getColor(this, R.color.indicator_tertiary));
        loadingIndicator.setContainerColor(
                ContextCompat.getColor(this, android.R.color.transparent));

        BottomNavigationView nav = findViewById(R.id.nav);
        nav.setOnItemSelectedListener(item -> {
            showTab(item.getItemId());
            return true;
        });
        nav.setSelectedItemId(R.id.nav_result);

        technicalView.setText(platformContext());

        executor.execute(this::runTest);
    }

    private void showTab(int itemId) {
        boolean showResult = itemId == R.id.nav_result;
        resultTab.setVisibility(showResult ? View.VISIBLE : View.GONE);
        detailsTab.setVisibility(showResult ? View.GONE : View.VISIBLE);
    }

    @Override
    protected void onDestroy() {
        destroyed = true;
        executor.shutdownNow();
        super.onDestroy();
    }

    private void runTest() {
        Result result;
        try {
            result = probe();
        } catch (Exception e) {
            result = new Result(R.string.verdict_failed, Outcome.FAIL,
                    R.drawable.ic_verdict_fail, describe(e), null);
        }

        if (destroyed) {
            return;
        }
        final Result rendered = result;
        runOnUiThread(() -> render(rendered));
    }

    private void render(Result result) {
        int containerRes;
        int onContainerRes;
        switch (result.outcome) {
            case PASS:
                containerRes = R.color.verdict_pass_container;
                onContainerRes = R.color.verdict_on_pass_container;
                break;
            case UNKNOWN:
                containerRes = R.color.verdict_unknown_container;
                onContainerRes = R.color.verdict_on_unknown_container;
                break;
            default:
                containerRes = R.color.verdict_fail_container;
                onContainerRes = R.color.verdict_on_fail_container;
                break;
        }

        verdictCard.setCardBackgroundColor(ContextCompat.getColor(this, containerRes));
        int onContainer = ContextCompat.getColor(this, onContainerRes);
        verdictIcon.setImageResource(result.icon);
        verdictIcon.setColorFilter(onContainer);
        verdictView.setTextColor(onContainer);
        verdictView.setText(result.verdictRes);
        detailsView.setText(result.details);
        if (result.technical != null) {
            technicalView.setText(result.technical);
        }

        loading.setVisibility(View.GONE);
        verdictCard.setVisibility(View.VISIBLE);
    }

    private Result probe() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
        keyStore.load(null);
        deleteIfPresent(keyStore);

        Result result;
        String cleanupFailure = null;
        try {
            result = generateResult();
        } finally {
            cleanupFailure = deleteIfPresent(keyStore);
        }
        return cleanupFailure == null
                ? result
                : new Result(result.verdictRes, result.outcome, result.icon,
                        result.details + "\n\n" + cleanupFailure, result.technical);
    }

    private static Result generateResult() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
        generator.initialize(new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(
                        KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
                        KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setKeySize(KEY_SIZE_BITS)
                .build());

        KeyPair pair = generator.generateKeyPair();

        KeyInfo info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE)
                .getKeySpec(pair.getPrivate(), KeyInfo.class);

        String roundTrip;
        boolean roundTripOk;
        try {
            roundTrip = "PASS (" + signAndVerify(pair) + ")";
            roundTripOk = true;
        } catch (Exception e) {
            roundTripOk = false;
            roundTrip = "FAIL - " + describe(e);
        }

        Backing backing = detectBacking(info);

        int verdictRes;
        Outcome outcome;
        if (!roundTripOk) {
            verdictRes = R.string.verdict_malfunctioning;
            outcome = Outcome.FAIL;
        } else if (backing == Backing.HARDWARE) {
            verdictRes = R.string.verdict_pass;
            outcome = Outcome.PASS;
        } else if (backing == Backing.SOFTWARE) {
            verdictRes = R.string.verdict_software;
            outcome = Outcome.FAIL;
        } else {
            verdictRes = R.string.verdict_unknown;
            outcome = Outcome.UNKNOWN;
        }

        @DrawableRes int icon;
        switch (outcome) {
            case PASS:
                icon = R.drawable.ic_verdict_pass;
                break;
            case UNKNOWN:
                icon = R.drawable.ic_verdict_unknown;
                break;
            default:
                icon = R.drawable.ic_verdict_fail;
                break;
        }

        StringBuilder details = new StringBuilder();
        details.append("Sign/verify round trip: ").append(roundTrip).append('\n');
        details.append("Security level: ").append(securityLevel(info)).append('\n');
        details.append("Inside secure hardware: ")
                .append(insideSecureHardwareText(info)).append('\n');
        details.append("Origin: ").append(originName(info.getOrigin())).append('\n');
        details.append("Key size: ").append(info.getKeySize()).append(" bits\n");
        details.append("Android: ").append(Build.VERSION.RELEASE)
                .append(" (API ").append(Build.VERSION.SDK_INT).append(')');

        if (backing == Backing.SOFTWARE && Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            details.append("\n\nNote: on Android 11 and older this verdict rests on")
                    .append(" isInsideSecureHardware(), which is deprecated and known to")
                    .append(" report false on some builds that do have a Trusted Environment.")
                    .append(" Android 12+ uses getSecurityLevel() instead.");
        } else if (backing == Backing.UNKNOWN) {
            details.append("\n\nNote: the Keystore did not report a usable backing value.")
                    .append(" This is not the same as a software-backed Keystore, and it may")
                    .append(" indicate a malfunctioning secure element.");
        }

        return new Result(verdictRes, outcome, icon, details.toString(), platformContext(info));
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

    /**
     * Reads the Keystore's backing. A failure to read is reported as UNKNOWN rather than
     * folded into SOFTWARE, because "could not tell" and "not hardware backed" are different
     * diagnoses and conflating them would misdirect someone debugging a broken secure element.
     */
    private static Backing detectBacking(KeyInfo info) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                switch (info.getSecurityLevel()) {
                    case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                    case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                        return Backing.HARDWARE;
                    case KeyProperties.SECURITY_LEVEL_SOFTWARE:
                        return Backing.SOFTWARE;
                    default:
                        return Backing.UNKNOWN;
                }
            }
            Boolean inside = isInsideSecureHardware(info);
            if (inside == null) {
                return Backing.UNKNOWN;
            }
            return inside ? Backing.HARDWARE : Backing.SOFTWARE;
        } catch (Exception e) {
            return Backing.UNKNOWN;
        }
    }

    /** @return true, false, or null if the call itself failed. */
    @SuppressWarnings("deprecation")
    private static Boolean isInsideSecureHardware(KeyInfo info) {
        try {
            return info.isInsideSecureHardware();
        } catch (Exception e) {
            return null;
        }
    }

    private static String insideSecureHardwareText(KeyInfo info) {
        Boolean inside = isInsideSecureHardware(info);
        return inside == null ? "unavailable" : inside.toString();
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
                        return "Undetermined";
                }
            }
            Boolean inside = isInsideSecureHardware(info);
            if (inside == null) {
                return "Undetermined";
            }
            return inside ? "Hardware (reported)" : "Software (reported)";
        } catch (Exception e) {
            return "Undetermined";
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

    private static String platformContext() {
        return platformContext(null);
    }

    private static String platformContext(KeyInfo info) {
        StringBuilder sb = new StringBuilder();

        sb.append("Provider: ");
        try {
            Provider provider = KeyStore.getInstance(ANDROID_KEY_STORE).getProvider();
            sb.append(provider.getName())
                    .append(' ').append(provider.getVersion());
        } catch (Exception e) {
            sb.append("unavailable - ").append(e.getClass().getSimpleName());
        }

        sb.append("\nVerdict API: ");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            sb.append("KeyInfo.getSecurityLevel()");
        } else {
            sb.append("KeyInfo.isInsideSecureHardware()\n")
                    .append("  (deprecated; getSecurityLevel() needs API 31+)");
        }

        sb.append("\nSoC: ").append(socDescription());
        sb.append("\nHardware: ").append(Build.HARDWARE);
        sb.append("\nBoard: ").append(Build.BOARD);

        if (info != null) {
            sb.append("\nPurposes: 0x").append(Integer.toHexString(info.getPurposes()));
            sb.append("\nDigests: ").append(join(info.getDigests()));
            sb.append("\nPaddings: ").append(join(info.getSignaturePaddings()));
            sb.append("\nAuth required: ").append(info.isUserAuthenticationRequired());
        }

        return sb.toString();
    }

    private static String socDescription() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            String manufacturer = Build.SOC_MANUFACTURER;
            String model = Build.SOC_MODEL;
            if (manufacturer != null || model != null) {
                return manufacturer + " " + model;
            }
        }
        return Build.MANUFACTURER + " " + Build.MODEL;
    }

    private static String join(String[] values) {
        if (values == null || values.length == 0) {
            return "(none reported)";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(values[i]);
        }
        return sb.toString();
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

    private enum Backing {
        HARDWARE,
        SOFTWARE,
        UNKNOWN
    }

    private enum Outcome {
        PASS,
        UNKNOWN,
        FAIL
    }

    private static final class Result {
        @StringRes
        final int verdictRes;
        final Outcome outcome;
        @DrawableRes
        final int icon;
        final String details;
        final String technical;

        Result(@StringRes int verdictRes, Outcome outcome, @DrawableRes int icon,
                String details, String technical) {
            this.verdictRes = verdictRes;
            this.outcome = outcome;
            this.icon = icon;
            this.details = details;
            this.technical = technical;
        }
    }
}

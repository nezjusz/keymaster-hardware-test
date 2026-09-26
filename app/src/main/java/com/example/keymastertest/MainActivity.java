package com.example.keymastertest;

import android.app.Activity;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.widget.TextView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.X509EncodedKeySpec;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView view = new TextView(this);
        view.setTextSize(18);
        view.setPadding(30, 30, 30, 30);
        view.setText("Testing Keymaster...");

        setContentView(view);

        new Thread(() -> {
            String result;

            try {
                String alias = "KeymasterTestKey";

                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias);
                }

                KeyPairGenerator generator =
                        KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_RSA,
                                "AndroidKeyStore");

                generator.initialize(
                        new KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_SIGN |
                                KeyProperties.PURPOSE_VERIFY)
                                .setDigests(
                                        KeyProperties.DIGEST_SHA256,
                                        KeyProperties.DIGEST_SHA512)
                                .build());

                KeyPair pair = generator.generateKeyPair();

                KeyFactory factory =
                        KeyFactory.getInstance(
                                KeyProperties.KEY_ALGORITHM_RSA,
                                "AndroidKeyStore");

                KeyInfo info = factory.getKeySpec(
                        pair.getPrivate(),
                        KeyInfo.class);

                result =
                        "KEYMASTER TEST\n\n" +
                        "Key generated: YES\n\n" +
                        "Inside Secure Hardware: " +
                        info.isInsideSecureHardware() + "\n\n" +
                        "Origin: " +
                        info.getOrigin() + "\n\n" +
                        "Key size: " +
                        info.getKeySize() + " bits";

            } catch (Throwable e) {
                result =
                        "KEYMASTER TEST\n\n" +
                        "FAILED\n\n" +
                        e.getClass().getName() +
                        "\n\n" +
                        String.valueOf(e.getMessage());
            }

            final String finalResult = result;
	    runOnUiThread(() -> view.setText(finalResult));

        }).start();
    }
}

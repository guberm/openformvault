package dev.guber.openformvault;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class LocalAutofillStore {
    private static final String PREFS = "openformvault_autofill_cache";
    private static final String KEY_ALIAS = "openformvault.autofill.cache.v1";
    private static final String CIPHERTEXT = "ciphertext";
    private static final String NONCE = "nonce";
    private static final SecureRandom RANDOM = new SecureRandom();

    private LocalAutofillStore() {}

    static void save(Context context, JSONObject vaultJson) throws Exception {
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(128, nonce));
        byte[] ciphertext = cipher.doFinal(vaultJson.toString().getBytes(StandardCharsets.UTF_8));
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putString(NONCE, Base64.encodeToString(nonce, Base64.NO_WRAP))
            .apply();
    }

    static JSONObject load(Context context) throws Exception {
        String ciphertextText = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(CIPHERTEXT, "");
        String nonceText = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(NONCE, "");
        if (ciphertextText.isEmpty() || nonceText.isEmpty()) return new JSONObject().put("items", new org.json.JSONArray());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(128, Base64.decode(nonceText, Base64.NO_WRAP)));
        byte[] plaintext = cipher.doFinal(Base64.decode(ciphertextText, Base64.NO_WRAP));
        return new JSONObject(new String(plaintext, StandardCharsets.UTF_8));
    }

    private static SecretKey getOrCreateKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return ((KeyStore.SecretKeyEntry) keyStore.getEntry(KEY_ALIAS, null)).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .build());
        return generator.generateKey();
    }
}

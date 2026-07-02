package dev.guber.openformvault;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.provider.Settings;
import android.os.Bundle;
import android.text.InputType;
import android.graphics.Color;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity {
    private static final String DEFAULT_SERVER_URL = "https://openformvault.guber.dev";
    private static final int PBKDF2_ITERATIONS = 310000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private LinearLayout root;
    private TextView status;
    private TextView authTitle;
    private EditText serverUrlInput;
    private EditText usernameInput;
    private EditText passwordInput;
    private EditText confirmPasswordInput;
    private CheckBox showAuthPasswords;
    private Button loginButton;
    private Button createAccountButton;
    private Button backToLoginButton;
    private EditText titleInput;
    private EditText urlInput;
    private EditText loginUsernameInput;
    private EditText loginPasswordInput;
    private EditText searchInput;
    private EditText otpSecretInput;
    private EditText notesInput;
    private EditText passkeyRpIdInput;
    private EditText passkeyCredentialIdInput;
    private LinearLayout list;
    private LinearLayout authGroup;
    private LinearLayout vaultGroup;
    private LinearLayout formGroup;
    private LinearLayout settingsGroup;
    private Spinner themeModeInput;
    private boolean registerMode = false;

    private String token = "";
    private String masterPassword = "";
    private String username = "";
    private long revision = 0;
    private String editingId = "";
    private final List<String> revealedPasswords = new ArrayList<>();
    private final List<LoginItem> items = new ArrayList<>();

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        serverUrlInput.setText(getPreferences(MODE_PRIVATE).getString("serverUrl", DEFAULT_SERVER_URL));
        usernameInput.setText(getPreferences(MODE_PRIVATE).getString("username", ""));
        token = getPreferences(MODE_PRIVATE).getString("token", "");
        revision = getPreferences(MODE_PRIVATE).getLong("revision", 0);
        setStatus("Ready. Log in or create an account.");
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        applyTheme(getPreferences(MODE_PRIVATE).getString("themeMode", "System"));
        scroll.addView(root);

        TextView title = label("OpenFormVault", 24);
        TextView subtitle = label("Your private password vault for logins, passkeys, authenticator codes, and secure notes.", 15);
        title.setTextColor(Color.rgb(17, 24, 39));
        subtitle.setTextColor(Color.rgb(107, 114, 128));
        status = label("Starting…", 15);
        status.setTextColor(Color.rgb(71, 85, 105));
        serverUrlInput = input("Server URL");
        usernameInput = input("Username");
        passwordInput = input("Master password");
        confirmPasswordInput = input("Confirm master password");
        passwordInput.setInputType(0x00000081); // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD
        confirmPasswordInput.setInputType(0x00000081);
        showAuthPasswords = new CheckBox(this);
        showAuthPasswords.setText("👁 Show password");
        showAuthPasswords.setOnCheckedChangeListener((button, checked) -> setAuthPasswordVisibility(checked));

        root.addView(title);
        root.addView(subtitle);
        root.addView(status);

        authGroup = group();
        authTitle = label("Sign in", 20);
        authGroup.addView(authTitle);
        authGroup.addView(label("Server", 14));
        authGroup.addView(serverUrlInput);
        authGroup.addView(usernameInput);
        authGroup.addView(passwordInput);
        authGroup.addView(confirmPasswordInput);
        authGroup.addView(showAuthPasswords);
        LinearLayout authActions = group();
        authActions.setOrientation(LinearLayout.HORIZONTAL);
        loginButton = button("Log in", v -> authenticate(false));
        createAccountButton = button("Create account", v -> { if (registerMode) authenticate(true); else showRegister(); });
        backToLoginButton = button("Back to login", v -> showLogin());
        authActions.addView(loginButton);
        authActions.addView(createAccountButton);
        authActions.addView(backToLoginButton);
        authGroup.addView(authActions);
        root.addView(authGroup);

        vaultGroup = group();
        vaultGroup.addView(label("Vault", 20));
        LinearLayout vaultActions = group();
        vaultActions.setOrientation(LinearLayout.HORIZONTAL);
        vaultActions.addView(button("+ Add", v -> { clearForm(); showForm(); }));
        vaultActions.addView(button("⚙", v -> toggleSettings()));
        vaultGroup.addView(vaultActions);
        searchInput = input("Search vault");
        searchInput.setSingleLine(true);
        searchInput.setOnEditorActionListener((v, actionId, event) -> { renderItems(); return false; });
        vaultGroup.addView(searchInput);
        list = new LinearLayout(this);
        list.setOrientation(LinearLayout.VERTICAL);
        vaultGroup.addView(list);
        root.addView(vaultGroup);

        formGroup = group();
        formGroup.addView(label("Add or edit login", 20));
        titleInput = input("Title");
        urlInput = input("URL");
        loginUsernameInput = input("Login username");
        loginPasswordInput = input("Login password");
        loginPasswordInput.setInputType(0x00000081);
        otpSecretInput = input("OTP/TOTP secret");
        notesInput = input("Notes");
        passkeyRpIdInput = input("Passkey RP ID");
        passkeyCredentialIdInput = input("Passkey credential ID");
        formGroup.addView(titleInput);
        formGroup.addView(urlInput);
        formGroup.addView(loginUsernameInput);
        formGroup.addView(loginPasswordInput);
        formGroup.addView(button("Generate password", v -> generatePassword()));
        formGroup.addView(otpSecretInput);
        formGroup.addView(notesInput);
        formGroup.addView(passkeyRpIdInput);
        formGroup.addView(passkeyCredentialIdInput);
        formGroup.addView(button("Save", v -> saveLogin()));
        formGroup.addView(button("Cancel", v -> { clearForm(); showVault(); }));
        root.addView(formGroup);

        settingsGroup = group();
        settingsGroup.addView(label("Settings", 20));
        settingsGroup.addView(label("Theme", 14));
        themeModeInput = new Spinner(this);
        ArrayAdapter<String> themeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[] { "System", "Light", "Dark" });
        themeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        themeModeInput.setAdapter(themeAdapter);
        String savedTheme = getPreferences(MODE_PRIVATE).getString("themeMode", "System");
        themeModeInput.setSelection("Dark".equals(savedTheme) ? 2 : ("Light".equals(savedTheme) ? 1 : 0));
        settingsGroup.addView(themeModeInput);
        settingsGroup.addView(button("Apply theme", v -> setThemeMode()));
        settingsGroup.addView(button("Security report", v -> showSecurityReport()));
        settingsGroup.addView(button("Android Autofill settings", v -> openAutofillSettings()));
        settingsGroup.addView(button("Lock", v -> { masterPassword = ""; token = ""; items.clear(); renderItems(); setStatus("Locked."); showLogin(); }));
        settingsGroup.addView(button("Test connection", v -> runAsync(() -> {
            JSONObject health = request("GET", "/health", null, false);
            setStatus(health.optString("product", "OpenFormVault") + " is online.");
        })));
        settingsGroup.addView(button("Sync now", v -> runAsync(this::pullRemote)));
        settingsGroup.addView(button("Force upload", v -> runAsync(this::pushRemote)));
        root.addView(settingsGroup);

        setContentView(scroll);
        renderItems();
        showLogin();
    }

    private LinearLayout group() {
        LinearLayout group = new LinearLayout(this);
        group.setOrientation(LinearLayout.VERTICAL);
        group.setPadding(0, 6, 0, 6);
        return group;
    }

    private void showAuth() {
        authGroup.setVisibility(View.VISIBLE);
        vaultGroup.setVisibility(View.GONE);
        formGroup.setVisibility(View.GONE);
        settingsGroup.setVisibility(View.GONE);
    }

    private void showLogin() {
        registerMode = false;
        authTitle.setText("Sign in");
        confirmPasswordInput.setVisibility(View.GONE);
        loginButton.setVisibility(View.VISIBLE);
        backToLoginButton.setVisibility(View.GONE);
        setAuthPasswordVisibility(showAuthPasswords.isChecked());
        showAuth();
    }

    private void showRegister() {
        registerMode = true;
        authTitle.setText("Create account");
        confirmPasswordInput.setVisibility(View.VISIBLE);
        loginButton.setVisibility(View.GONE);
        backToLoginButton.setVisibility(View.VISIBLE);
        setAuthPasswordVisibility(showAuthPasswords.isChecked());
        showAuth();
    }

    private void setAuthPasswordVisibility(boolean visible) {
        int type = InputType.TYPE_CLASS_TEXT | (visible ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD : InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passwordInput.setInputType(type);
        confirmPasswordInput.setInputType(type);
        passwordInput.setSelection(passwordInput.length());
        confirmPasswordInput.setSelection(confirmPasswordInput.length());
    }

    private void showVault() {
        authGroup.setVisibility(View.GONE);
        vaultGroup.setVisibility(View.VISIBLE);
        formGroup.setVisibility(View.GONE);
        settingsGroup.setVisibility(View.GONE);
    }

    private void showForm() {
        authGroup.setVisibility(View.GONE);
        vaultGroup.setVisibility(View.VISIBLE);
        formGroup.setVisibility(View.VISIBLE);
        settingsGroup.setVisibility(View.GONE);
    }

    private void toggleSettings() {
        authGroup.setVisibility(View.GONE);
        vaultGroup.setVisibility(View.VISIBLE);
        formGroup.setVisibility(View.GONE);
        settingsGroup.setVisibility(settingsGroup.getVisibility() == View.VISIBLE ? View.GONE : View.VISIBLE);
    }

    private TextView label(String text, int sp) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sp);
        view.setPadding(0, 8, 0, 8);
        return view;
    }

    private EditText input(String hint) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setSingleLine(true);
        if ("Server URL".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        } else if ("Username".equals(hint) || "Login username".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        } else if ("URL".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        }
        return input;
    }

    private void openAutofillSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE);
            intent.putExtra("android.provider.extra.AUTOFILL_SERVICE_COMPONENT_NAME", new ComponentName(this, OpenFormVaultAutofillService.class).flattenToString());
            startActivity(intent);
        } catch (Exception ex) {
            try { startActivity(new Intent(Settings.ACTION_SETTINGS)); } catch (Exception ignored) {}
        }
    }

    private Button button(String text, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(text);
        button.setOnClickListener(listener);
        if ("Log in".equals(text) || "+ Add".equals(text) || "Save".equals(text) || "Create account".equals(text)) {
            button.setTextColor(Color.WHITE);
            button.setBackgroundColor(Color.rgb(37, 99, 235));
        } else {
            button.setTextColor(Color.rgb(31, 41, 55));
            button.setBackgroundColor(Color.rgb(229, 231, 235));
        }
        return button;
    }

    private void generatePassword() {
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";
        StringBuilder password = new StringBuilder();
        for (int i = 0; i < 24; i++) password.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        loginPasswordInput.setText(password.toString());
        setStatus("Generated a strong password.");
    }

    private void setThemeMode() {
        String mode = themeModeInput.getSelectedItem().toString();
        getPreferences(MODE_PRIVATE).edit().putString("themeMode", mode).apply();
        applyTheme(mode);
        setStatus("Theme set to " + mode + ".");
    }

    private void applyTheme(String mode) {
        boolean dark = "Dark".equals(mode);
        if (root != null) root.setBackgroundColor(dark ? Color.rgb(15, 23, 42) : Color.rgb(247, 248, 251));
        if (status != null) status.setTextColor(dark ? Color.rgb(226, 232, 240) : Color.rgb(71, 85, 105));
    }

    private void showSecurityReport() {
        int weak = 0, missingOtp = 0, httpOnly = 0, duplicates = 0;
        for (int i = 0; i < items.size(); i++) {
            LoginItem item = items.get(i);
            if (item.password.length() < 12) weak++;
            if (item.otpSecret.isEmpty()) missingOtp++;
            if (item.url.toLowerCase().startsWith("http://")) httpOnly++;
            for (int j = i + 1; j < items.size(); j++) if (!item.password.isEmpty() && item.password.equals(items.get(j).password)) duplicates++;
        }
        setStatus("Security: " + weak + " weak, " + duplicates + " reused, " + httpOnly + " HTTP-only, " + missingOtp + " missing OTP.");
    }

    private void authenticate(boolean register) {
        runAsync(() -> {
            masterPassword = passwordInput.getText().toString();
            username = usernameInput.getText().toString().trim();
            if (register && !masterPassword.equals(confirmPasswordInput.getText().toString())) throw new Exception("Passwords do not match.");
            JSONObject body = new JSONObject().put("username", username).put("password", masterPassword);
            JSONObject response = request("POST", register ? "/v1/users/register" : "/v1/session", body, false);
            token = response.getString("token");
            getPreferences(MODE_PRIVATE).edit()
                .putString("serverUrl", serverUrl())
                .putString("username", username)
                .putString("token", token)
                .apply();
            try { pullRemote(); } catch (Exception ex) { saveLocalVault(); setStatus("Signed in. Add your first login; it will sync automatically."); runOnUiThread(this::showVault); }
        });
    }

    private void saveLogin() {
        if (masterPassword.isEmpty()) { setStatus("Log in first."); return; }
        LoginItem item = new LoginItem(
            editingId.isEmpty() ? UUID.randomUUID().toString() : editingId,
            titleInput.getText().toString(),
            urlInput.getText().toString(),
            loginUsernameInput.getText().toString(),
            loginPasswordInput.getText().toString(),
            otpSecretInput.getText().toString().replace(" ", ""),
            notesInput.getText().toString(),
            passkeyRpIdInput.getText().toString(),
            passkeyCredentialIdInput.getText().toString());
        int existing = -1;
        for (int i = 0; i < items.size(); i++) if (items.get(i).id.equals(item.id)) existing = i;
        if (existing >= 0) items.set(existing, item); else items.add(item);
        clearForm();
        try { saveLocalVault(); } catch (Exception ex) { setStatus("Local save failed: " + ex.getMessage()); }
        renderItems();
        showVault();
        autoSync(existing >= 0 ? "Login updated. Auto-syncing…" : "Login saved. Auto-syncing…");
    }

    private void clearForm() {
        editingId = "";
        titleInput.setText(""); urlInput.setText(""); loginUsernameInput.setText(""); loginPasswordInput.setText("");
        otpSecretInput.setText(""); notesInput.setText(""); passkeyRpIdInput.setText(""); passkeyCredentialIdInput.setText("");
    }

    private void editLogin(LoginItem item) {
        editingId = item.id;
        titleInput.setText(item.title); urlInput.setText(item.url); loginUsernameInput.setText(item.username); loginPasswordInput.setText(item.password);
        otpSecretInput.setText(item.otpSecret); notesInput.setText(item.notes); passkeyRpIdInput.setText(item.passkeyRpId); passkeyCredentialIdInput.setText(item.passkeyCredentialId);
        setStatus("Editing " + item.title + ".");
        showForm();
    }

    private void autoSync(String message) {
        setStatus(message);
        if (token.isEmpty() || masterPassword.isEmpty()) return;
        runAsync(this::pushRemote);
    }

    private void renderItems() {
        list.removeAllViews();
        String q = searchInput == null ? "" : searchInput.getText().toString().trim().toLowerCase();
        if (items.isEmpty()) { list.addView(label("No logins yet. Tap + Add to add one.", 15)); return; }
        int shown = 0;
        for (LoginItem item : new ArrayList<>(items)) {
            String haystack = (item.title + " " + item.url + " " + item.username + " " + item.notes).toLowerCase();
            if (!q.isEmpty() && !haystack.contains(q)) continue;
            shown++;
            TextView row = label(item.title + "\n" + item.url + "\n" + item.username + (item.otpSecret.isEmpty() ? "" : "\nOTP enabled") + (item.passkeyCredentialId.isEmpty() ? "" : "\nPasskey: " + item.passkeyRpId), 15);
            Button view = button((revealedPasswords.contains(item.id) ? "Hide " : "View ") + item.title, v -> { if (revealedPasswords.contains(item.id)) revealedPasswords.remove(item.id); else revealedPasswords.add(item.id); renderItems(); });
            if (revealedPasswords.contains(item.id)) list.addView(label("Password: " + item.password, 14));
            Button edit = button("Edit " + item.title, v -> editLogin(item));
            Button delete = button("Delete " + item.title, v -> { items.remove(item); revealedPasswords.remove(item.id); try { saveLocalVault(); } catch (Exception ignored) {} renderItems(); autoSync("Deleted. Auto-syncing…"); });
            list.addView(row);
            list.addView(view);
            list.addView(edit);
            list.addView(delete);
        }
        if (shown == 0) list.addView(label("No matching logins.", 15));
    }

    private void pullRemote() throws Exception {
        JSONObject snapshot = request("GET", "/v1/vault/snapshot", null, true);
        decryptIntoItems(snapshot);
        revision = snapshot.getLong("revision");
        getPreferences(MODE_PRIVATE).edit().putLong("revision", revision).apply();
        saveEncryptedSnapshot(snapshot);
        LocalAutofillStore.save(this, vaultJson());
        renderOnUi();
        setStatus("Pulled revision " + revision + ".");
        runOnUiThread(this::showVault);
    }

    private void pushRemote() throws Exception {
        JSONObject encrypted = encryptVault();
        encrypted.put("baseRevision", revision == 0 ? JSONObject.NULL : revision);
        JSONObject result = request("PUT", "/v1/vault/snapshot", encrypted, true);
        revision = result.getLong("revision");
        getPreferences(MODE_PRIVATE).edit().putLong("revision", revision).apply();
        saveLocalVault();
        setStatus("Pushed revision " + revision + ".");
    }

    private void saveLocalVault() throws Exception { saveEncryptedSnapshot(encryptVault()); LocalAutofillStore.save(this, vaultJson()); }

    private void saveEncryptedSnapshot(JSONObject encrypted) {
        getPreferences(MODE_PRIVATE).edit()
            .putString("ciphertext", encrypted.optString("ciphertext"))
            .putString("nonce", encrypted.optString("nonce"))
            .putString("salt", encrypted.optString("salt"))
            .apply();
    }

    private JSONObject vaultJson() throws Exception {
        JSONArray arr = new JSONArray();
        for (LoginItem item : items) arr.put(item.toJson());
        return new JSONObject().put("items", arr);
    }

    private JSONObject encryptVault() throws Exception {
        String existingSalt = getPreferences(MODE_PRIVATE).getString("salt", "");
        byte[] salt = existingSalt.isEmpty() ? randomBytes(16) : Base64.getDecoder().decode(existingSalt);
        byte[] nonce = randomBytes(12);
        SecretKeySpec key = deriveKey(masterPassword, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
        byte[] ciphertext = cipher.doFinal(vaultJson().toString().getBytes(StandardCharsets.UTF_8));
        return new JSONObject()
            .put("ciphertext", Base64.getEncoder().encodeToString(ciphertext))
            .put("nonce", Base64.getEncoder().encodeToString(nonce))
            .put("salt", Base64.getEncoder().encodeToString(salt))
            .put("algorithm", "AES-GCM")
            .put("kdf", "PBKDF2-SHA256-310000");
    }

    private void decryptIntoItems(JSONObject snapshot) throws Exception {
        SecretKeySpec key = deriveKey(masterPassword, Base64.getDecoder().decode(snapshot.getString("salt")));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Base64.getDecoder().decode(snapshot.getString("nonce"))));
        String json = new String(cipher.doFinal(Base64.getDecoder().decode(snapshot.getString("ciphertext"))), StandardCharsets.UTF_8);
        JSONArray arr = new JSONObject(json).optJSONArray("items");
        items.clear();
        if (arr != null) for (int i = 0; i < arr.length(); i++) items.add(LoginItem.fromJson(arr.getJSONObject(i)));
    }

    private SecretKeySpec deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        byte[] key = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, "AES");
    }

    private byte[] randomBytes(int count) { byte[] bytes = new byte[count]; RANDOM.nextBytes(bytes); return bytes; }

    private JSONObject request(String method, String path, JSONObject body, boolean auth) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(serverUrl() + path).openConnection();
        connection.setConnectTimeout(12000);
        connection.setReadTimeout(12000);
        connection.setRequestMethod(method);
        connection.setRequestProperty("Accept", "application/json");
        if (auth) connection.setRequestProperty("Authorization", "Bearer " + token);
        if (body != null) {
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            try (OutputStream out = connection.getOutputStream()) { out.write(body.toString().getBytes(StandardCharsets.UTF_8)); }
        }
        int code = connection.getResponseCode();
        BufferedReader reader = new BufferedReader(new InputStreamReader(code >= 400 ? connection.getErrorStream() : connection.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder text = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) text.append(line);
        connection.disconnect();
        if (code < 200 || code >= 300) throw new Exception("HTTP " + code + " " + text);
        return text.length() == 0 ? new JSONObject() : new JSONObject(text.toString());
    }

    private String serverUrl() { return serverUrlInput.getText().toString().trim().replaceAll("/+$", ""); }
    private void setStatus(String text) { runOnUiThread(() -> status.setText(text)); }
    private void renderOnUi() { runOnUiThread(this::renderItems); }
    private void runAsync(ThrowingRunnable runnable) { new Thread(() -> { try { runnable.run(); } catch (Exception ex) { setStatus(ex.getMessage()); } }).start(); }

    interface ThrowingRunnable { void run() throws Exception; }

    static final class LoginItem {
        final String id, title, url, username, password, otpSecret, notes, passkeyRpId, passkeyCredentialId;
        LoginItem(String id, String title, String url, String username, String password, String otpSecret, String notes, String passkeyRpId, String passkeyCredentialId) {
            this.id = id; this.title = title; this.url = url; this.username = username; this.password = password; this.otpSecret = otpSecret; this.notes = notes; this.passkeyRpId = passkeyRpId; this.passkeyCredentialId = passkeyCredentialId;
        }
        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject().put("id", id).put("title", title).put("url", url).put("username", username).put("password", password).put("otpSecret", otpSecret).put("notes", notes);
            if (!passkeyRpId.isEmpty() || !passkeyCredentialId.isEmpty()) json.put("passkey", new JSONObject().put("rpId", passkeyRpId).put("credentialId", passkeyCredentialId).put("userHandle", ""));
            return json;
        }
        static LoginItem fromJson(JSONObject json) {
            JSONObject passkey = json.optJSONObject("passkey");
            return new LoginItem(json.optString("id"), json.optString("title"), json.optString("url"), json.optString("username"), json.optString("password"), json.optString("otpSecret"), json.optString("notes"), passkey == null ? "" : passkey.optString("rpId"), passkey == null ? "" : passkey.optString("credentialId"));
        }
    }
}

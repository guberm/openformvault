package dev.guber.openformvault;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.provider.Settings;
import android.provider.Settings.Secure;
import android.os.Bundle;
import android.text.InputType;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
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
import java.time.Instant;
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
    private Spinner itemTypeInput;
    private EditText itemFolderInput;
    private CheckBox itemPinnedInput;
    private EditText otpSecretInput;
    private EditText notesInput;
    private EditText passkeyRpIdInput;
    private EditText passkeyCredentialIdInput;
    private EditText identityFullNameInput;
    private EditText identityEmailInput;
    private EditText identityPhoneInput;
    private EditText identityAddressInput;
    private EditText bookmarkDescriptionInput;
    private LinearLayout list;
    private LinearLayout authGroup;
    private LinearLayout vaultGroup;
    private LinearLayout formGroup;
    private LinearLayout settingsGroup;
    private Spinner themeModeInput;
    private Spinner startupScreenInput;
    private Spinner autoLockInput;
    private boolean registerMode = false;
    private long lastPausedAt = 0L;

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

    @Override protected void onPause() {
        super.onPause();
        if (!masterPassword.isEmpty()) {
            getPreferences(MODE_PRIVATE).edit().putLong("lastPausedAt", System.currentTimeMillis()).apply();
        }
    }

    @Override protected void onResume() {
        super.onResume();
        long thresholdMs = autoLockMillis();
        if (thresholdMs <= 0) return;
        long pausedAt = getPreferences(MODE_PRIVATE).getLong("lastPausedAt", 0L);
        if (pausedAt > 0 && !masterPassword.isEmpty() && System.currentTimeMillis() - pausedAt >= thresholdMs) {
            masterPassword = "";
            token = "";
            items.clear();
            renderItems();
            setStatus("Auto-locked after inactivity.");
            showLogin();
        }
    }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(24), dp(72), dp(24), dp(32));
        applyTheme(getPreferences(MODE_PRIVATE).getString("themeMode", "System"));
        scroll.addView(root, new ScrollView.LayoutParams(ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));

        TextView title = label("OpenFormVault", 22);
        TextView subtitle = caption("Private password vault for logins, passkeys, authenticator codes, and secure notes.");
        title.setTextColor(Color.rgb(17, 24, 39));
        status = caption("Ready to sign in or create an account.");
        status.setTextColor(Color.rgb(71, 85, 105));
        status.setPadding(dp(12), dp(10), dp(12), dp(10));
        status.setBackground(roundedRect(Color.rgb(239, 246, 255), Color.rgb(191, 219, 254), 14));

        serverUrlInput = input("Server URL");
        usernameInput = input("Email or username");
        passwordInput = input("Master password");
        confirmPasswordInput = input("Confirm master password");
        passwordInput.setInputType(0x00000081); // TYPE_CLASS_TEXT | TYPE_TEXT_VARIATION_PASSWORD
        confirmPasswordInput.setInputType(0x00000081);
        showAuthPasswords = new CheckBox(this);
        showAuthPasswords.setText("Show passwords");
        showAuthPasswords.setTextSize(15);
        showAuthPasswords.setOnCheckedChangeListener((button, checked) -> setAuthPasswordVisibility(checked));
        LinearLayout.LayoutParams authCheckParams = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        authCheckParams.bottomMargin = dp(12);
        showAuthPasswords.setLayoutParams(authCheckParams);

        root.addView(title);
        root.addView(subtitle);
        root.addView(status);

        authGroup = group();
        authGroup.setPadding(dp(20), dp(20), dp(20), dp(20));
        authGroup.setBackground(roundedRect(Color.WHITE, Color.rgb(226, 232, 240), 18));
        authTitle = label("Sign in", 18);
        authGroup.addView(authTitle);
        authGroup.addView(caption("Server"));
        authGroup.addView(serverUrlInput);
        authGroup.addView(usernameInput);
        authGroup.addView(passwordInput);
        authGroup.addView(confirmPasswordInput);
        authGroup.addView(showAuthPasswords);
        LinearLayout authActions = group();
        authActions.setOrientation(LinearLayout.VERTICAL);
        loginButton = button("Log in", v -> authenticate(false));
        createAccountButton = button("Create account", v -> { if (registerMode) authenticate(true); else showRegister(); });
        backToLoginButton = button("Back to sign in", v -> showLogin());
        styleAuthPrimary(loginButton);
        styleAuthPrimary(createAccountButton);
        styleAuthSecondary(backToLoginButton);
        authActions.addView(loginButton);
        authActions.addView(createAccountButton);
        authActions.addView(backToLoginButton);
        authGroup.addView(authActions);
        root.addView(authGroup);

        vaultGroup = group();
        vaultGroup.addView(label("Vault", 18));
        LinearLayout vaultActions = group();
        vaultActions.setOrientation(LinearLayout.HORIZONTAL);
        vaultActions.addView(button("+ Add", v -> { clearForm(); showForm(); }));
        vaultActions.addView(button("Settings", v -> toggleSettings()));
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
        formGroup.addView(label("Add or edit item", 18));
        itemTypeInput = new Spinner(this);
        ArrayAdapter<String> itemTypeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[] { "login", "identity", "note", "bookmark", "passkey" });
        itemTypeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        itemTypeInput.setAdapter(itemTypeAdapter);
        itemFolderInput = input("Folder");
        itemPinnedInput = new CheckBox(this);
        itemPinnedInput.setText("Pinned");
        titleInput = input("Title");
        urlInput = input("URL");
        loginUsernameInput = input("Login username");
        loginPasswordInput = input("Login password");
        loginPasswordInput.setInputType(0x00000081);
        identityFullNameInput = input("Identity full name");
        identityEmailInput = input("Identity email");
        identityPhoneInput = input("Identity phone");
        identityAddressInput = input("Identity address");
        bookmarkDescriptionInput = input("Bookmark description");
        otpSecretInput = input("OTP/TOTP secret");
        notesInput = input("Notes / Safenote");
        passkeyRpIdInput = input("Passkey RP ID");
        passkeyCredentialIdInput = input("Passkey credential ID");
        formGroup.addView(caption("Item type"));
        formGroup.addView(itemTypeInput);
        formGroup.addView(itemFolderInput);
        formGroup.addView(itemPinnedInput);
        formGroup.addView(titleInput);
        formGroup.addView(urlInput);
        formGroup.addView(loginUsernameInput);
        formGroup.addView(loginPasswordInput);
        formGroup.addView(button("Generate password", v -> generatePassword()));
        formGroup.addView(identityFullNameInput);
        formGroup.addView(identityEmailInput);
        formGroup.addView(identityPhoneInput);
        formGroup.addView(identityAddressInput);
        formGroup.addView(bookmarkDescriptionInput);
        formGroup.addView(otpSecretInput);
        formGroup.addView(notesInput);
        formGroup.addView(passkeyRpIdInput);
        formGroup.addView(passkeyCredentialIdInput);
        formGroup.addView(button("Save", v -> saveLogin()));
        formGroup.addView(button("Cancel", v -> { clearForm(); showVault(); }));
        root.addView(formGroup);

        settingsGroup = group();
        settingsGroup.addView(label("Settings", 18));
        settingsGroup.addView(caption("Startup screen"));
        startupScreenInput = new Spinner(this);
        ArrayAdapter<String> startupAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[] { "Vault", "Add item", "Settings" });
        startupAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        startupScreenInput.setAdapter(startupAdapter);
        String startup = getPreferences(MODE_PRIVATE).getString("startupScreen", "Vault");
        startupScreenInput.setSelection("Add item".equals(startup) ? 1 : ("Settings".equals(startup) ? 2 : 0));
        settingsGroup.addView(startupScreenInput);
        settingsGroup.addView(button("Save startup screen", v -> saveStartupScreen()));
        settingsGroup.addView(caption("Auto-lock"));
        autoLockInput = new Spinner(this);
        ArrayAdapter<String> autoLockAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[] { "Off", "30 sec", "1 min", "5 min" });
        autoLockAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        autoLockInput.setAdapter(autoLockAdapter);
        String autoLock = getPreferences(MODE_PRIVATE).getString("autoLock", "Off");
        autoLockInput.setSelection("30 sec".equals(autoLock) ? 1 : ("1 min".equals(autoLock) ? 2 : ("5 min".equals(autoLock) ? 3 : 0)));
        settingsGroup.addView(autoLockInput);
        settingsGroup.addView(button("Save auto-lock", v -> saveAutoLock()));
        settingsGroup.addView(caption("Theme"));
        themeModeInput = new Spinner(this);
        ArrayAdapter<String> themeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, new String[] { "System", "Light", "Dark" });
        themeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        themeModeInput.setAdapter(themeAdapter);
        String savedTheme = getPreferences(MODE_PRIVATE).getString("themeMode", "System");
        themeModeInput.setSelection("Dark".equals(savedTheme) ? 2 : ("Light".equals(savedTheme) ? 1 : 0));
        settingsGroup.addView(themeModeInput);
        settingsGroup.addView(button("Apply theme", v -> setThemeMode()));
        settingsGroup.addView(button("Security report", v -> showSecurityReport()));
        settingsGroup.addView(button("Trusted devices", v -> runAsync(this::showTrustedDevices)));
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

    private void showStartupDestination() {
        String startup = getPreferences(MODE_PRIVATE).getString("startupScreen", "Vault");
        if ("Add item".equals(startup)) showForm();
        else if ("Settings".equals(startup)) toggleSettings();
        else showVault();
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
        view.setPadding(0, dp(4), 0, dp(4));
        view.setTextColor(Color.rgb(17, 24, 39));
        return view;
    }

    private TextView caption(String text) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(14);
        view.setPadding(0, 0, 0, dp(6));
        view.setTextColor(Color.rgb(100, 116, 139));
        return view;
    }

    private EditText input(String hint) {
        EditText input = new EditText(this);
        input.setHint(hint);
        input.setSingleLine(true);
        input.setTextSize(16);
        input.setTextColor(Color.rgb(17, 24, 39));
        input.setHintTextColor(Color.rgb(148, 163, 184));
        input.setBackground(roundedRect(Color.WHITE, Color.rgb(203, 213, 225), 14));
        input.setPadding(dp(14), dp(14), dp(14), dp(14));
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(12);
        input.setLayoutParams(params);
        if ("Server URL".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        } else if ("Email or username".equals(hint) || "Login username".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        } else if ("URL".equals(hint)) {
            input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        }
        return input;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private GradientDrawable roundedRect(int fill, int stroke, int radiusDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        drawable.setStroke(dp(1), stroke);
        return drawable;
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
        button.setAllCaps(false);
        button.setTextSize(15);
        button.setMinHeight(dp(44));
        button.setPadding(dp(14), dp(12), dp(14), dp(12));
        button.setOnClickListener(listener);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.rightMargin = dp(8);
        params.bottomMargin = dp(8);
        button.setLayoutParams(params);
        if ("Log in".equals(text) || "+ Add".equals(text) || "Save".equals(text) || "Create account".equals(text)) {
            button.setTextColor(Color.WHITE);
            button.setBackground(roundedRect(Color.rgb(37, 99, 235), Color.rgb(37, 99, 235), 14));
        } else {
            button.setTextColor(Color.rgb(31, 41, 55));
            button.setBackground(roundedRect(Color.rgb(241, 245, 249), Color.rgb(203, 213, 225), 14));
        }
        return button;
    }

    private void styleAuthPrimary(Button button) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(10);
        button.setLayoutParams(params);
        button.setTextColor(Color.WHITE);
        button.setBackground(roundedRect(Color.rgb(37, 99, 235), Color.rgb(37, 99, 235), 14));
    }

    private void styleAuthSecondary(Button button) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.bottomMargin = dp(4);
        button.setLayoutParams(params);
        button.setTextColor(Color.rgb(31, 41, 55));
        button.setBackground(roundedRect(Color.rgb(255, 255, 255), Color.rgb(203, 213, 225), 14));
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

    private void saveStartupScreen() {
        String startup = startupScreenInput.getSelectedItem().toString();
        getPreferences(MODE_PRIVATE).edit().putString("startupScreen", startup).apply();
        setStatus("Startup screen set to " + startup + ".");
    }

    private void saveAutoLock() {
        String autoLock = autoLockInput.getSelectedItem().toString();
        getPreferences(MODE_PRIVATE).edit().putString("autoLock", autoLock).apply();
        setStatus("Auto-lock set to " + autoLock + ".");
    }

    private long autoLockMillis() {
        String autoLock = getPreferences(MODE_PRIVATE).getString("autoLock", "Off");
        if ("30 sec".equals(autoLock)) return 30_000L;
        if ("1 min".equals(autoLock)) return 60_000L;
        if ("5 min".equals(autoLock)) return 300_000L;
        return 0L;
    }

    private void applyTheme(String mode) {
        boolean dark = "Dark".equals(mode);
        if (root != null) root.setBackgroundColor(dark ? Color.rgb(15, 23, 42) : Color.rgb(247, 248, 251));
        if (status != null) {
            status.setTextColor(dark ? Color.rgb(226, 232, 240) : Color.rgb(71, 85, 105));
            status.setBackground(roundedRect(dark ? Color.rgb(30, 41, 59) : Color.rgb(239, 246, 255), dark ? Color.rgb(51, 65, 85) : Color.rgb(191, 219, 254), 14));
        }
        if (authGroup != null) authGroup.setBackground(roundedRect(dark ? Color.rgb(15, 23, 42) : Color.WHITE, dark ? Color.rgb(51, 65, 85) : Color.rgb(226, 232, 240), 18));
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
            try { pullRemote(); } catch (Exception ex) { saveLocalVault(); setStatus("Signed in. Add your first login; it will sync automatically."); runOnUiThread(this::showStartupDestination); }
        });
    }

    private void saveLogin() {
        if (masterPassword.isEmpty()) { setStatus("Log in first."); return; }
        String type = itemTypeInput.getSelectedItem().toString();
        int existing = -1;
        for (int i = 0; i < items.size(); i++) if (items.get(i).id.equals(editingId)) existing = i;
        String now = Instant.now().toString();
        LoginItem prior = existing >= 0 ? items.get(existing) : null;
        LoginItem item = new LoginItem(
            editingId.isEmpty() ? UUID.randomUUID().toString() : editingId,
            type,
            titleInput.getText().toString(),
            urlInput.getText().toString(),
            loginUsernameInput.getText().toString(),
            loginPasswordInput.getText().toString(),
            otpSecretInput.getText().toString().replace(" ", ""),
            notesInput.getText().toString(),
            passkeyRpIdInput.getText().toString(),
            passkeyCredentialIdInput.getText().toString(),
            itemFolderInput.getText().toString(),
            itemPinnedInput.isChecked(),
            identityFullNameInput.getText().toString(),
            identityEmailInput.getText().toString(),
            identityPhoneInput.getText().toString(),
            identityAddressInput.getText().toString(),
            bookmarkDescriptionInput.getText().toString(),
            prior == null ? now : prior.createdAt,
            now,
            prior == null ? "" : prior.lastUsedAt);
        if (existing >= 0) items.set(existing, item); else items.add(item);
        clearForm();
        try { saveLocalVault(); } catch (Exception ex) { setStatus("Local save failed: " + ex.getMessage()); }
        renderItems();
        showVault();
        autoSync(existing >= 0 ? "Item updated. Auto-syncing…" : "Item saved. Auto-syncing…");
    }

    private void clearForm() {
        editingId = "";
        itemTypeInput.setSelection(0);
        itemFolderInput.setText("");
        itemPinnedInput.setChecked(false);
        titleInput.setText(""); urlInput.setText(""); loginUsernameInput.setText(""); loginPasswordInput.setText("");
        identityFullNameInput.setText(""); identityEmailInput.setText(""); identityPhoneInput.setText(""); identityAddressInput.setText("");
        bookmarkDescriptionInput.setText("");
        otpSecretInput.setText(""); notesInput.setText(""); passkeyRpIdInput.setText(""); passkeyCredentialIdInput.setText("");
    }

    private void editLogin(LoginItem item) {
        editingId = item.id;
        String[] types = new String[] { "login", "identity", "note", "bookmark", "passkey" };
        for (int i = 0; i < types.length; i++) if (types[i].equals(item.type)) itemTypeInput.setSelection(i);
        itemFolderInput.setText(item.folder);
        itemPinnedInput.setChecked(item.pinned);
        titleInput.setText(item.title); urlInput.setText(item.url); loginUsernameInput.setText(item.username); loginPasswordInput.setText(item.password);
        identityFullNameInput.setText(item.identityFullName); identityEmailInput.setText(item.identityEmail); identityPhoneInput.setText(item.identityPhone); identityAddressInput.setText(item.identityAddress);
        bookmarkDescriptionInput.setText(item.bookmarkDescription);
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
        if (items.isEmpty()) { list.addView(label("No saved items yet. Tap + Add to add one.", 15)); return; }
        int shown = 0;
        for (LoginItem item : new ArrayList<>(items)) {
            String haystack = (item.type + " " + item.title + " " + item.url + " " + item.username + " " + item.notes + " " + item.folder + " " + item.identityFullName + " " + item.identityEmail + " " + item.identityPhone + " " + item.identityAddress + " " + item.bookmarkDescription).toLowerCase();
            if (!q.isEmpty() && !haystack.contains(q)) continue;
            shown++;
            String summary;
            if ("identity".equals(item.type)) summary = item.identityFullName + "\n" + item.identityEmail + "\n" + item.identityPhone;
            else if ("note".equals(item.type)) summary = item.notes.isEmpty() ? "Encrypted note" : item.notes;
            else if ("bookmark".equals(item.type)) summary = item.url + (item.bookmarkDescription.isEmpty() ? "" : "\n" + item.bookmarkDescription);
            else summary = item.url + "\n" + item.username + (item.otpSecret.isEmpty() ? "" : "\nOTP enabled") + (item.passkeyCredentialId.isEmpty() ? "" : "\nPasskey: " + item.passkeyRpId);
            TextView row = label(item.title + "\n" + summary + (item.folder.isEmpty() ? "" : "\nFolder: " + item.folder) + (item.pinned ? "\nPinned" : ""), 15);
            list.addView(row);
            if (revealedPasswords.contains(item.id)) list.addView(label(secretText(item), 14));
            Button view = button((revealedPasswords.contains(item.id) ? "Hide " : "View ") + item.title, v -> { if (revealedPasswords.contains(item.id)) revealedPasswords.remove(item.id); else revealedPasswords.add(item.id); if ("login".equals(item.type) || "passkey".equals(item.type)) markLastUsed(item.id); renderItems(); });
            Button edit = button("Edit " + item.title, v -> editLogin(item));
            Button delete = button("Delete " + item.title, v -> { items.remove(item); revealedPasswords.remove(item.id); try { saveLocalVault(); } catch (Exception ignored) {} renderItems(); autoSync("Deleted. Auto-syncing…"); });
            list.addView(view);
            edit.setText("Edit " + item.title);
            list.addView(edit);
            list.addView(delete);
            if (!item.otpSecret.isEmpty()) list.addView(button("Show OTP", v -> setStatus("OTP for " + item.title + ": " + generateTotp(item.otpSecret))));
        }
        if (shown == 0) list.addView(label("No matching items.", 15));
    }

    private String secretText(LoginItem item) {
        if ("identity".equals(item.type)) return "Full name: " + item.identityFullName + "\nEmail: " + item.identityEmail + "\nPhone: " + item.identityPhone + "\nAddress: " + item.identityAddress;
        if ("note".equals(item.type)) return "Safenote:\n" + item.notes;
        if ("bookmark".equals(item.type)) return "Bookmark: " + item.url + "\n" + item.bookmarkDescription;
        return "Password: " + item.password;
    }

    private void markLastUsed(String id) {
        String now = Instant.now().toString();
        for (int i = 0; i < items.size(); i++) {
            LoginItem item = items.get(i);
            if (item.id.equals(id)) {
                items.set(i, item.withLastUsedAt(now));
                break;
            }
        }
    }

    private String generateTotp(String base32) {
        byte[] key = base32Decode(base32);
        long counter = System.currentTimeMillis() / 1000L / 30L;
        byte[] msg = new byte[8];
        for (int i = 7; i >= 0; i--) { msg[i] = (byte)(counter & 0xff); counter >>>= 8; }
        try {
            javax.crypto.Mac hmac = javax.crypto.Mac.getInstance("HmacSHA1");
            hmac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = hmac.doFinal(msg);
            int offset = hash[hash.length - 1] & 0x0f;
            int code = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format("%06d", code % 1_000_000);
        } catch (Exception ex) {
            return "OTP unavailable";
        }
    }

    private byte[] base32Decode(String input) {
        final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        String upper = input.toUpperCase();
        StringBuilder bits = new StringBuilder();
        for (int i = 0; i < upper.length(); i++) {
            char ch = upper.charAt(i);
            int idx = alphabet.indexOf(ch);
            if (idx >= 0) bits.append(String.format("%5s", Integer.toBinaryString(idx)).replace(' ', '0'));
        }
        ArrayList<Byte> bytes = new ArrayList<>();
        for (int i = 0; i + 8 <= bits.length(); i += 8) bytes.add((byte) Integer.parseInt(bits.substring(i, i + 8), 2));
        byte[] out = new byte[bytes.size()];
        for (int i = 0; i < bytes.size(); i++) out[i] = bytes.get(i);
        return out;
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
        runOnUiThread(this::showStartupDestination);
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
        connection.setRequestProperty("X-OpenFormVault-Device-Id", deviceId());
        connection.setRequestProperty("X-OpenFormVault-Device-Name", deviceName());
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
    private String deviceId() {
        String existing = getPreferences(MODE_PRIVATE).getString("deviceId", "");
        if (!existing.isEmpty()) return existing;
        String androidId = Secure.getString(getContentResolver(), Secure.ANDROID_ID);
        String stable = UUID.nameUUIDFromBytes((androidId + ":openformvault").getBytes(StandardCharsets.UTF_8)).toString();
        getPreferences(MODE_PRIVATE).edit().putString("deviceId", stable).apply();
        return stable;
    }
    private String deviceName() {
        String existing = getPreferences(MODE_PRIVATE).getString("deviceName", "");
        if (!existing.isEmpty()) return existing;
        String value = android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL;
        getPreferences(MODE_PRIVATE).edit().putString("deviceName", value).apply();
        return value;
    }
    private void showTrustedDevices() throws Exception {
        JSONObject response = request("GET", "/v1/devices", null, true);
        JSONArray devices = response.optJSONArray("devices");
        if (devices == null || devices.length() == 0) { setStatus("No trusted devices yet."); return; }
        List<String> names = new ArrayList<>();
        for (int i = 0; i < devices.length(); i++) {
            JSONObject device = devices.getJSONObject(i);
            names.add(device.optString("deviceName") + (device.optBoolean("current") ? " (this device)" : ""));
        }
        setStatus("Trusted devices: " + String.join(", ", names));
    }
    private void setStatus(String text) { runOnUiThread(() -> status.setText(text)); }
    private void renderOnUi() { runOnUiThread(this::renderItems); }
    private void runAsync(ThrowingRunnable runnable) { new Thread(() -> { try { runnable.run(); } catch (Exception ex) { setStatus(ex.getMessage()); } }).start(); }

    interface ThrowingRunnable { void run() throws Exception; }

    static final class LoginItem {
        final String id, type, title, url, username, password, otpSecret, notes, passkeyRpId, passkeyCredentialId, folder, identityFullName, identityEmail, identityPhone, identityAddress, bookmarkDescription, createdAt, updatedAt, lastUsedAt;
        final boolean pinned;
        LoginItem(String id, String type, String title, String url, String username, String password, String otpSecret, String notes, String passkeyRpId, String passkeyCredentialId, String folder, boolean pinned, String identityFullName, String identityEmail, String identityPhone, String identityAddress, String bookmarkDescription, String createdAt, String updatedAt, String lastUsedAt) {
            this.id = id; this.type = type; this.title = title; this.url = url; this.username = username; this.password = password; this.otpSecret = otpSecret; this.notes = notes; this.passkeyRpId = passkeyRpId; this.passkeyCredentialId = passkeyCredentialId; this.folder = folder; this.pinned = pinned; this.identityFullName = identityFullName; this.identityEmail = identityEmail; this.identityPhone = identityPhone; this.identityAddress = identityAddress; this.bookmarkDescription = bookmarkDescription; this.createdAt = createdAt; this.updatedAt = updatedAt; this.lastUsedAt = lastUsedAt;
        }
        JSONObject toJson() throws Exception {
            JSONObject json = new JSONObject().put("id", id).put("type", type).put("title", title).put("url", url).put("username", username).put("password", password).put("otpSecret", otpSecret).put("notes", notes).put("folder", folder).put("pinned", pinned).put("createdAt", createdAt).put("updatedAt", updatedAt).put("lastUsedAt", lastUsedAt);
            json.put("identity", new JSONObject().put("fullName", identityFullName).put("email", identityEmail).put("phone", identityPhone).put("address", identityAddress));
            json.put("bookmark", new JSONObject().put("url", url).put("description", bookmarkDescription));
            if (!passkeyRpId.isEmpty() || !passkeyCredentialId.isEmpty()) json.put("passkey", new JSONObject().put("rpId", passkeyRpId).put("credentialId", passkeyCredentialId).put("userHandle", ""));
            return json;
        }
        LoginItem withLastUsedAt(String when) {
            return new LoginItem(id, type, title, url, username, password, otpSecret, notes, passkeyRpId, passkeyCredentialId, folder, pinned, identityFullName, identityEmail, identityPhone, identityAddress, bookmarkDescription, createdAt, updatedAt, when);
        }
        static LoginItem fromJson(JSONObject json) {
            JSONObject passkey = json.optJSONObject("passkey");
            JSONObject identity = json.optJSONObject("identity");
            JSONObject bookmark = json.optJSONObject("bookmark");
            return new LoginItem(json.optString("id"), json.optString("type", inferLegacyType(json)), json.optString("title"), json.optString("url"), json.optString("username"), json.optString("password"), json.optString("otpSecret"), json.optString("notes"), passkey == null ? "" : passkey.optString("rpId"), passkey == null ? "" : passkey.optString("credentialId"), json.optString("folder"), json.optBoolean("pinned"), identity == null ? json.optString("fullName") : identity.optString("fullName"), identity == null ? json.optString("email") : identity.optString("email"), identity == null ? json.optString("phone") : identity.optString("phone"), identity == null ? json.optString("address") : identity.optString("address"), bookmark == null ? json.optString("description") : bookmark.optString("description"), json.optString("createdAt", Instant.now().toString()), json.optString("updatedAt", Instant.now().toString()), json.optString("lastUsedAt", ""));
        }
        private static String inferLegacyType(JSONObject json) {
            if (json.has("identity") || json.has("fullName") || json.has("email") || json.has("phone") || json.has("address")) return "identity";
            if ((json.optString("notes").length() > 0) && json.optString("url").isEmpty() && json.optString("username").isEmpty() && json.optString("password").isEmpty()) return "note";
            if (json.has("bookmark") || (!json.optString("url").isEmpty() && json.optString("username").isEmpty() && json.optString("password").isEmpty() && json.optString("description").length() > 0)) return "bookmark";
            if (json.has("passkey")) return "passkey";
            return "login";
        }
    }
}

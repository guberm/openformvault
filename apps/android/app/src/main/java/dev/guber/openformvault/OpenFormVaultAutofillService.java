package dev.guber.openformvault;

import android.app.assist.AssistStructure;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.Dataset;
import android.service.autofill.FillCallback;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveInfo;
import android.service.autofill.SaveRequest;
import android.text.InputType;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class OpenFormVaultAutofillService extends AutofillService {
    @Override public void onFillRequest(FillRequest request, CancellationSignal cancellationSignal, FillCallback callback) {
        try {
            AssistStructure structure = request.getFillContexts().get(request.getFillContexts().size() - 1).getStructure();
            Fields fields = findFields(structure);
            if (fields.password == null && fields.username == null) { callback.onSuccess(null); return; }

            JSONArray items = LocalAutofillStore.load(this).optJSONArray("items");
            if (items == null || items.length() == 0) { callback.onSuccess(null); return; }

            FillResponse.Builder response = new FillResponse.Builder();
            int added = 0;
            for (int i = 0; i < items.length(); i++) {
                JSONObject item = items.optJSONObject(i);
                if (item == null) continue;
                String title = item.optString("title", item.optString("url", "OpenFormVault"));
                String username = item.optString("username", "");
                String password = item.optString("password", "");
                if (username.isEmpty() && password.isEmpty()) continue;
                RemoteViews presentation = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
                presentation.setTextViewText(android.R.id.text1, title + (username.isEmpty() ? "" : " — " + username));
                Dataset.Builder dataset = new Dataset.Builder(presentation);
                if (fields.username != null && !username.isEmpty()) dataset.setValue(fields.username, AutofillValue.forText(username), presentation);
                if (fields.password != null && !password.isEmpty()) dataset.setValue(fields.password, AutofillValue.forText(password), presentation);
                response.addDataset(dataset.build());
                added++;
            }
            if (added == 0) { callback.onSuccess(null); return; }
            List<AutofillId> ids = new ArrayList<>();
            if (fields.username != null) ids.add(fields.username);
            if (fields.password != null) ids.add(fields.password);
            if (!ids.isEmpty()) response.setSaveInfo(new SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, ids.toArray(new AutofillId[0])).build());
            callback.onSuccess(response.build());
        } catch (Exception ex) {
            callback.onFailure("OpenFormVault autofill failed: " + ex.getMessage());
        }
    }

    @Override public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        callback.onSuccess();
    }

    private static Fields findFields(AssistStructure structure) {
        Fields fields = new Fields();
        for (int i = 0; i < structure.getWindowNodeCount(); i++) visit(structure.getWindowNodeAt(i).getRootViewNode(), fields);
        return fields;
    }

    private static void visit(AssistStructure.ViewNode node, Fields fields) {
        FieldKind kind = classify(node);
        AutofillId id = node.getAutofillId();
        if (id != null && kind == FieldKind.USERNAME && fields.username == null) fields.username = id;
        if (id != null && kind == FieldKind.PASSWORD && fields.password == null) fields.password = id;
        for (int i = 0; i < node.getChildCount(); i++) visit(node.getChildAt(i), fields);
    }

    private static FieldKind classify(AssistStructure.ViewNode node) {
        String hints = String.join(" ", node.getAutofillHints() == null ? new String[]{} : node.getAutofillHints()).toLowerCase(Locale.ROOT);
        if (matchesPassword(hints)) return FieldKind.PASSWORD;
        if (matchesUsername(hints)) return FieldKind.USERNAME;
        int inputType = node.getInputType();
        int variation = inputType & InputType.TYPE_MASK_VARIATION;
        if (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD || variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD) return FieldKind.PASSWORD;
        String haystack = (safe(node.getHint()) + " " + safe(node.getIdEntry()) + " " + safe(node.getText()) + " " + safe(node.getContentDescription())).toLowerCase(Locale.ROOT);
        if (matchesPassword(haystack)) return FieldKind.PASSWORD;
        if (matchesUsername(haystack)) return FieldKind.USERNAME;
        return FieldKind.OTHER;
    }

    private static boolean matchesPassword(String text) { return text.contains("password") || text.contains("passcode") || text.contains("pwd"); }
    private static boolean matchesUsername(String text) { return text.contains("username") || text.contains("user name") || text.contains("email") || text.contains("login"); }
    private static String safe(CharSequence value) { return value == null ? "" : value.toString(); }

    private enum FieldKind { USERNAME, PASSWORD, OTHER }
    private static final class Fields { AutofillId username; AutofillId password; }
}

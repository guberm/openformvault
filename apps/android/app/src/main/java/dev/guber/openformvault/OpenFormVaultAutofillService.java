package dev.guber.openformvault;

import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillRequest;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveRequest;

public class OpenFormVaultAutofillService extends AutofillService {
    @Override public void onFillRequest(FillRequest request, android.os.CancellationSignal cancellationSignal, FillCallback callback) {
        callback.onSuccess(null);
    }

    @Override public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        callback.onSuccess();
    }
}

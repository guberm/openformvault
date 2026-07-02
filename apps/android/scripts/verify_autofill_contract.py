from pathlib import Path
root = Path(__file__).resolve().parents[1]
manifest = (root / 'app/src/main/AndroidManifest.xml').read_text()
service = (root / 'app/src/main/java/dev/guber/openformvault/OpenFormVaultAutofillService.java').read_text()
main = (root / 'app/src/main/java/dev/guber/openformvault/MainActivity.java').read_text()
store = (root / 'app/src/main/java/dev/guber/openformvault/LocalAutofillStore.java').read_text()
checks = {
    'manifest declares AutofillService': 'android.service.autofill.AutofillService' in manifest,
    'manifest binds autofill permission': 'android.permission.BIND_AUTOFILL_SERVICE' in manifest,
    'service extends AutofillService': 'extends AutofillService' in service,
    'service implements onFillRequest': 'onFillRequest' in service,
    'service builds FillResponse': 'FillResponse.Builder' in service,
    'service builds Dataset': 'Dataset.Builder' in service,
    'service exposes SaveInfo': 'SaveInfo.Builder' in service,
    'local autofill cache uses AndroidKeyStore': 'AndroidKeyStore' in store,
    'main writes autofill cache': 'LocalAutofillStore.save' in main,
    'settings opens autofill setup': 'ACTION_REQUEST_SET_AUTOFILL_SERVICE' in main,
    'registration has confirm password': 'Confirm master password' in main and 'Passwords do not match' in main,
    'auth has password eye control': '👁 Show password' in main,
    'server field is on auth page': 'authGroup.addView(serverUrlInput)' in main,
}
failed = [name for name, ok in checks.items() if not ok]
for name, ok in checks.items():
    print(f'{"PASS" if ok else "FAIL"}: {name}')
if failed:
    raise SystemExit('Missing contract checks: ' + ', '.join(failed))

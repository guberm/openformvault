# OpenFormVault Android

Native Android scaffold for v1.

Current verified scaffold:

- launchable app;
- declares a real `AutofillService` with `BIND_AUTOFILL_SERVICE`;
- no vault secrets or old alpha code copied.

Planned stack: Kotlin/Compose/Room/WorkManager/Keystore/BiometricPrompt. The first scaffold is Java-only to keep the initial build small and deterministic.

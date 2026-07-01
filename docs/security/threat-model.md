# Security and zero-knowledge threat model

## Primary goal

The server must not be able to decrypt vault data.

## Server must never receive

- master password;
- Secret Key;
- vault root key;
- item keys;
- plaintext item title/domain/username/password/notes/TOTP/custom fields;
- decrypted folder/tag/search metadata.

## Key hierarchy target

```text
Master Password + high-entropy Secret Key
  -> Argon2id/domain-separated KDF
  -> Account Unlock Key / Root KEK
  -> User Private Key or Root Vault Key
  -> Vault Key(s)
  -> per-item Item Key(s)
  -> item ciphertext
```

## Account auth vs vault unlock

Account authentication authorizes sync access. Vault unlock decrypts vault material locally. They are separate domains.

Open design item: evaluate OPAQUE for account login; SRP is fallback if implementation maturity blocks OPAQUE.

## Browser extension caveat

Chrome extensions run in a weaker local-security environment than native clients. Content scripts are attacker-influenced and must never receive bulk decrypted vault data. They receive only explicit fill payloads for the current user action.

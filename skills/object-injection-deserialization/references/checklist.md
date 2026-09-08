# Object injection & deserialization checklist

Use this checklist wherever PHP serialization is used.

- [ ] No `unserialize()` / `maybe_unserialize()` runs on user input, uploads, or remote data.
- [ ] JSON is the default interchange format for structured data.
- [ ] `is_serialized()` is not treated as a security guarantee.
- [ ] Where `unserialize()` is unavoidable, `allowed_classes => false` is set.
- [ ] User-controlled serialized blobs are not stored in options/meta/transients.
- [ ] Decoded JSON is validated for expected shape before use.
- [ ] Values from decoded data are sanitized/escaped before output or storage.

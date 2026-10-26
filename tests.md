# Testing

`envelope`'s test suite is GTest-based and lives in `tests/envelope.unittest.cxx`.

## Building and running

```
cmake -S . -B build
cmake --build build --target envelope_test
```

Then either run it directly:

```
./build/tests/envelope_test
./build/tests/envelope_test --gtest_filter='Envelope.RejectsTamperedMaskWhenSigned'
```

or through CTest:

```
ctest --test-dir build --output-on-failure
```

Tests are enabled by default and require GTest. Pass `-DENVELOPE_BUILD_TESTS=OFF` to
build the `envelope` library without its tests.

## What's covered

- Round trips: no layers, base64 only, compress only, encrypt only, sign only, all four
  combined, and an empty payload.
- Tamper detection: flipping a payload byte, and — the case that specifically exercises
  the mask-downgrade defense described in [`readme.md`](readme.md) — flipping the mask
  byte itself, both correctly rejected once signing is enabled.
- Wrong key rejected, independently, for both `encrypt_key` and `sign_key`.
- Bad magic number rejected.
- Unwrapping a signed blob with no `sign_key` configured is rejected, not silently
  treated as unsigned.
- `wrap()` refuses to proceed if `encrypt`/`sign` is requested without a validly-sized
  key, rather than silently skipping the layer.
- One `envelope_t` instance reused across several `wrap()`/`unwrap()` calls, confirming
  it's safe to keep around rather than reconstructing per call.


#pragma once

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace envelope {

inline constexpr size_t aes_256_key_size = 32;

class aes_256_key_t {
public:
  /// Constructs an all-zero key - a value that must never actually be used
  /// to encrypt anything; see config_t::encrypt_key for how a genuinely
  /// "not configured" key is represented instead.
  aes_256_key_t ( ) = default;

  aes_256_key_t (const std::array<std::byte, aes_256_key_size>& bytes) : bytes_(bytes) {  // NOLINT: implicit by design
  }

  aes_256_key_t (const aes_256_key_t&)            = default;
  aes_256_key_t& operator= (const aes_256_key_t&) = default;

  aes_256_key_t (aes_256_key_t&& other) noexcept : bytes_(other.bytes_) {
    OPENSSL_cleanse(other.bytes_.data( ), other.bytes_.size( ));
  }

  aes_256_key_t& operator= (aes_256_key_t&& other) noexcept {
    if ( this != &other ) {
      bytes_ = other.bytes_;
      OPENSSL_cleanse(other.bytes_.data( ), other.bytes_.size( ));
    }
    return *this;
  }

  ~aes_256_key_t ( ) {
    OPENSSL_cleanse(bytes_.data( ), bytes_.size( ));
  }

  /// @{
  /// Byte access, 0-indexed - `i` must be `< size()`, same precondition as
  /// `std::array::operator[]`.
  [[nodiscard]] std::byte&       operator[] (size_t i) noexcept { return bytes_[i]; }
  [[nodiscard]] const std::byte& operator[] (size_t i) const noexcept { return bytes_[i]; }
  /// @}

  void fill (std::byte v) noexcept {
    bytes_.fill(v);
  }

  [[nodiscard]] constexpr size_t size ( ) const noexcept {
    return aes_256_key_size;
  }

  [[nodiscard]] const std::array<std::byte, aes_256_key_size>& bytes ( ) const noexcept {
    return bytes_;
  }

private:
  std::array<std::byte, aes_256_key_size> bytes_ {};
};

class secure_bytes_t {
public:
  secure_bytes_t ( ) = default;

  secure_bytes_t (std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {  // NOLINT: implicit by design
  }

  secure_bytes_t(const secure_bytes_t&)                = default;
  secure_bytes_t& operator= (const secure_bytes_t&)     = default;
  secure_bytes_t(secure_bytes_t&&) noexcept             = default;
  secure_bytes_t& operator= (secure_bytes_t&&) noexcept = default;

  ~secure_bytes_t ( ) {
    OPENSSL_cleanse(bytes_.data( ), bytes_.size( ));
  }

  [[nodiscard]] bool   empty ( ) const noexcept { return bytes_.empty( ); }
  [[nodiscard]] size_t size ( ) const noexcept { return bytes_.size( ); }

  [[nodiscard]] const std::vector<std::byte>& bytes ( ) const noexcept {
    return bytes_;
  }

private:
  std::vector<std::byte> bytes_;
};

enum class base64_mode_t {
  none,      ///< Raw bytes in, raw bytes out - no text encoding at all.
  standard,  ///< RFC 4648 §4: `+`/`/` alphabet, `=` padding.
  url_safe,  ///< RFC 4648 §5: `-`/`_` alphabet, no padding - safe to drop
             ///< directly into a URL, a cookie, or a JWT-style token
             ///< without further escaping, which is the whole reason this
             ///< variant exists.
};

struct config_t {
  base64_mode_t base64 = base64_mode_t::standard;

  bool compress = false;  ///< zlib deflate.

  bool                          encrypt = false;  ///< AES-256-GCM.
  std::optional<aes_256_key_t>  encrypt_key;

  bool           sign = false;  ///< HMAC-SHA256.
  secure_bytes_t sign_key;
};

/// See hard_decisions_we_did/06-envelope-layer-order.md
///
/// @note Stateless and reusable: unlike `parameter_bytestream_t` in the
/// parent minesweeper repository, one envelope_t instance is safe to call
/// wrap()/unwrap() on repeatedly - each call is independent, nothing here
/// tracks an in-progress buffer.
class envelope_t {
public:
  explicit envelope_t (config_t config);

  /// @param data The payload to wrap. May be empty.
  /// @return The wrapped bytes (base64 text, if `config.base64` isn't
  /// `base64_mode_t::none`), or an error message - e.g. `encrypt` enabled
  /// without a valid `encrypt_key` - describing why wrapping failed.
  [[nodiscard]] std::expected<std::vector<std::byte>, std::string> wrap (std::span<const std::byte> data) const;

  /// Reverses whatever wrap() (with a matching `config` - specifically,
  /// the right key(s) for whichever layers the wire header says were
  /// used) produced.
  /// @param data Bytes previously returned by a wrap() call - from this or
  /// any other envelope_t configured with the same keys and `base64` mode.
  /// @return The original payload passed to wrap(), or an error message if
  /// `data` doesn't decode as a well-formed, correctly-signed/decryptable
  /// envelope (bad magic, failed signature or decryption, missing key,
  /// truncated input, ...).
  [[nodiscard]] std::expected<std::vector<std::byte>, std::string> unwrap (std::span<const std::byte> data) const;

private:
  config_t config_;
};

}  // namespace envelope

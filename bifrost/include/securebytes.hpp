#pragma once

#include <bifrost.hpp>
#include <cstddef>
#include <memory>
#include <openssl/crypto.h>

// ---------------------------------------------------------------------------
// SecureAllocator — wraps std::allocator so every deallocation calls
// OPENSSL_cleanse first, preventing secrets from lingering on the heap after
// a vector is freed or reallocated.
// ---------------------------------------------------------------------------
template <typename T> struct SecureAllocator : std::allocator<T> {
        using Base = std::allocator<T>;

        // Required by the standard allocator protocol so containers can rebind
        // the allocator to their internal node/value types.
        template <typename U> struct rebind {
                using other = SecureAllocator<U>;
        };

        SecureAllocator() noexcept = default;

        template <typename U>
        SecureAllocator(const SecureAllocator<U> &) noexcept {}

        void deallocate(T *p, size_t n) {
            if (p && n > 0)
                OPENSSL_cleanse(p, n * sizeof(T));
            Base::deallocate(p, n);
        }
};

// Two SecureAllocators are always considered equal (they carry no state),
// which allows container move/swap to work without reallocating.
template <typename T, typename U>
bool operator==(const SecureAllocator<T> &,
                const SecureAllocator<U> &) noexcept {
    return true;
}
template <typename T, typename U>
bool operator!=(const SecureAllocator<T> &,
                const SecureAllocator<U> &) noexcept {
    return false;
}

template <typename T> using SecureVector = std::vector<T, SecureAllocator<T>>;

// ---------------------------------------------------------------------------
// SecureBytes — a non-copyable byte buffer whose storage is wiped by
// OPENSSL_cleanse both in the allocator's deallocate path and explicitly in
// cleanse() / the destructor.  Use clone() when a deliberate copy is needed.
// ---------------------------------------------------------------------------
class SecureBytes {
        SecureVector<Byte> _data;

    public:
        SecureBytes() = default;

        explicit SecureBytes(size_t size)
            : _data(size) {}

        SecureBytes(const uint8_t *ptr, size_t len)
            : _data(ptr, ptr + len) {}

        // Implicit conversion from plain Bytes; avoids requiring callers to
        // spell out the iterator range every time.
        SecureBytes(const Bytes &data)
            : _data(data.begin(), data.end()) {} // NOLINT(*-explicit-*)

        // Non-copyable: copying a secret should be a conscious, named act.
        SecureBytes(const SecureBytes &) = delete;
        SecureBytes &operator=(const SecureBytes &) = delete;

        SecureBytes(SecureBytes &&other) noexcept
            : _data(std::move(other._data)) {}

        SecureBytes &operator=(SecureBytes &&other) noexcept {
            if (this != &other) {
                cleanse();
                _data = std::move(other._data);
            }
            return *this;
        }

        // cleanse() is called here and in SecureAllocator::deallocate; the
        // double wipe is harmless and ensures the bytes are always zeroed even
        // if the allocator path is somehow skipped (e.g. small-buffer
        // optimisation).
        ~SecureBytes() { cleanse(); }

        Byte *data() { return _data.data(); }
        const Byte *data() const { return _data.data(); }
        size_t size() const { return _data.size(); }
        bool empty() const { return _data.empty(); }
        void resize(size_t n) { _data.resize(n); }

        // Named copy constructor — makes intentional duplication explicit at
        // the call site without relying on a deleted copy constructor.
        SecureBytes clone() const {
            return SecureBytes(_data.data(), _data.size());
        }

        SecureVector<Byte>::iterator begin() { return _data.begin(); }
        SecureVector<Byte>::iterator end() { return _data.end(); }
        SecureVector<Byte>::const_iterator begin() const {
            return _data.begin();
        }
        SecureVector<Byte>::const_iterator end() const { return _data.end(); }

        // May be called at any point to eagerly wipe memory before the object
        // is destroyed (e.g. immediately after a key is no longer needed).
        void cleanse() {
            if (!_data.empty())
                OPENSSL_cleanse(_data.data(), _data.size());
        }
};

#pragma once

#include <TypeDefs.hpp>
#include <cstddef>
#include <memory>
#include <openssl/crypto.h>

template <typename T> struct SecureAllocator : std::allocator<T> {
        using Base = std::allocator<T>;

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

class SecureBytes {
    private:
        SecureVector<Byte> _data;

    public:
        SecureBytes() = default;
        explicit SecureBytes(size_t size)
            : _data(size) {}
        SecureBytes(const uint8_t *ptr, size_t len)
            : _data(ptr, ptr + len) {}
        SecureBytes(const Bytes &data)
            : _data(data.begin(), data.end()) {}

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

        ~SecureBytes() { cleanse(); }

        Byte *data() { return _data.data(); }
        const Byte *data() const { return _data.data(); }
        size_t size() const { return _data.size(); }
        bool empty() const { return _data.empty(); }
        void resize(size_t n) { _data.resize(n); }

        SecureBytes clone() const {
            return SecureBytes(_data.data(), _data.size());
        }

        SecureVector<Byte>::iterator begin() { return _data.begin(); }
        SecureVector<Byte>::iterator end() { return _data.end(); }
        SecureVector<Byte>::const_iterator begin() const {
            return _data.begin();
        }
        SecureVector<Byte>::const_iterator end() const { return _data.end(); }

        void cleanse() {
            if (!_data.empty())
                OPENSSL_cleanse(_data.data(), _data.size());
        }
};

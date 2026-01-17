#pragma once

#include <vector>
#include <cstddef>
#include <stdexcept>
#include <type_traits>
#include "error.hpp"


namespace crypto_utils {
namespace core {

/**
 * @brief Byte vector type (replaces cu_result)
 */
using byte_vector = std::vector<std::byte>;

/**
 * @brief Result type similar to C++23 std::expected
 *
 * Represents either a successful value or an error.
 *
 * @tparam T The value type for successful results
 */
template<typename T>
class result {
public:
    /**
     * @brief Construct a successful result
     */
    result(T value) : has_value_(true) {
        new (&value_) T(std::move(value));
    }

    /**
     * @brief Construct an error result
     */
    result(error err) : has_value_(false) {
        new (&error_) error(std::move(err));
    }

    /**
     * @brief Copy constructor
     */
    result(const result& other) : has_value_(other.has_value_) {
        if (has_value_) {
            new (&value_) T(other.value_);
        } else {
            new (&error_) error(other.error_);
        }
    }

    /**
     * @brief Move constructor
     */
    result(result&& other) noexcept : has_value_(other.has_value_) {
        if (has_value_) {
            new (&value_) T(std::move(other.value_));
        } else {
            new (&error_) error(std::move(other.error_));
        }
    }

    /**
     * @brief Destructor
     */
    ~result() {
        if (has_value_) {
            value_.~T();
        } else {
            error_.~error();
        }
    }

    /**
     * @brief Copy assignment
     */
    result& operator=(const result& other) {
        if (this != &other) {
            this->~result();
            has_value_ = other.has_value_;
            if (has_value_) {
                new (&value_) T(other.value_);
            } else {
                new (&error_) error(other.error_);
            }
        }
        return *this;
    }

    /**
     * @brief Move assignment
     */
    result& operator=(result&& other) noexcept {
        if (this != &other) {
            this->~result();
            has_value_ = other.has_value_;
            if (has_value_) {
                new (&value_) T(std::move(other.value_));
            } else {
                new (&error_) error(std::move(other.error_));
            }
        }
        return *this;
    }

    /**
     * @brief Check if result contains a value
     */
    bool has_value() const noexcept { return has_value_; }

    /**
     * @brief Check if result contains a value
     */
    explicit operator bool() const noexcept { return has_value_; }

    /**
     * @brief Get the value (throws if error)
     */
    T& value() & {
        if (!has_value_) {
            throw std::runtime_error("result has no value: " + error_.message());
        }
        return value_;
    }

    /**
     * @brief Get the value (throws if error)
     */
    const T& value() const & {
        if (!has_value_) {
            throw std::runtime_error("result has no value: " + error_.message());
        }
        return value_;
    }

    /**
     * @brief Get the value (throws if error)
     */
    T&& value() && {
        if (!has_value_) {
            throw std::runtime_error("result has no value: " + error_.message());
        }
        return std::move(value_);
    }

    /**
     * @brief Get the error (throws if value)
     */
    const error& error_value() const & {
        if (has_value_) {
            throw std::runtime_error("result has a value, not an error");
        }
        return error_;
    }

    /**
     * @brief Access value via pointer
     */
    T* operator->() { return &value(); }

    /**
     * @brief Access value via pointer
     */
    const T* operator->() const { return &value(); }

    /**
     * @brief Dereference to get value
     */
    T& operator*() & { return value(); }

    /**
     * @brief Dereference to get value
     */
    const T& operator*() const & { return value(); }

    /**
     * @brief Dereference to get value
     */
    T&& operator*() && { return std::move(value()); }

    /**
     * @brief Get value or default
     */
    template<typename U>
    T value_or(U&& default_value) const & {
        return has_value_ ? value_ : static_cast<T>(std::forward<U>(default_value));
    }

    /**
     * @brief Get value or default
     */
    template<typename U>
    T value_or(U&& default_value) && {
        return has_value_ ? std::move(value_) : static_cast<T>(std::forward<U>(default_value));
    }

private:
    union {
        T value_;
        error error_;
    };
    bool has_value_;
};

/**
 * @brief Specialization for void
 */
template<>
class result<void> {
public:
    result() : has_value_(true), error_() {}
    result(error err) : has_value_(false), error_(std::move(err)) {}

    bool has_value() const noexcept { return has_value_; }
    explicit operator bool() const noexcept { return has_value_; }

    void value() const {
        if (!has_value_) {
            throw std::runtime_error("result has no value: " + error_.message());
        }
    }

    const error& error_value() const & {
        if (has_value_) {
            throw std::runtime_error("result has a value, not an error");
        }
        return error_;
    }

private:
    bool has_value_;
    error error_;
};

} // namespace core
} // namespace crypto_utils

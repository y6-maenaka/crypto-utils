#pragma once

#include <concepts>
#include <string>
#include <string_view>
#include <cstddef>


namespace crypto_utils {
namespace core {

/**
 * @brief Concept for byte container types
 *
 * A type that provides data() and size() methods for byte access.
 */
template<typename T>
concept byte_container = requires(T t) {
    { t.data() } -> std::convertible_to<const void*>;
    { t.size() } -> std::convertible_to<std::size_t>;
};

/**
 * @brief Concept for string-like types
 */
template<typename T>
concept string_like = std::same_as<std::remove_cvref_t<T>, std::string> ||
                      std::same_as<std::remove_cvref_t<T>, std::string_view> ||
                      std::same_as<std::remove_cvref_t<T>, const char*> ||
                      std::same_as<std::remove_cvref_t<T>, char*>;

/**
 * @brief Concept for fixed-size containers
 */
template<typename T, std::size_t N>
concept fixed_size_container = requires(T t) {
    requires std::same_as<typename std::remove_cvref_t<T>::value_type,
                          typename std::remove_cvref_t<T>::value_type>;
    { t.size() } -> std::convertible_to<std::size_t>;
};

} // namespace core
} // namespace crypto_utils

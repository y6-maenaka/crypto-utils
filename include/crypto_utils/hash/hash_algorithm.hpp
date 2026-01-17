#pragma once

#include <span>
#include "../core/result.hpp"
#include "../core/concepts.hpp"


namespace crypto_utils {
namespace hash {

/**
 * @brief Base class for hash algorithms using CRTP pattern
 *
 * Provides a unified interface for all hash algorithms.
 *
 * @tparam Derived The derived hash algorithm class
 */
template<typename Derived>
class hash_algorithm {
public:
    /**
     * @brief Hash data from a byte container
     *
     * @tparam Container Type satisfying byte_container concept
     * @param input Data to hash
     * @return result<byte_vector> Hash digest or error
     */
    template<core::byte_container Container>
    static core::result<core::byte_vector> hash(const Container& input) {
        return Derived::hash_impl(
            static_cast<const std::byte*>(input.data()),
            input.size()
        );
    }

    /**
     * @brief Hash data from a string
     *
     * @tparam String Type satisfying string_like concept
     * @param input String to hash
     * @return result<byte_vector> Hash digest or error
     */
    template<core::string_like String>
    static core::result<core::byte_vector> hash(const String& input) {
        if constexpr (std::same_as<std::remove_cvref_t<String>, const char*> ||
                      std::same_as<std::remove_cvref_t<String>, char*>) {
            return hash_impl(
                reinterpret_cast<const std::byte*>(input),
                std::strlen(input)
            );
        } else {
            return hash_impl(
                reinterpret_cast<const std::byte*>(input.data()),
                input.size()
            );
        }
    }

    /**
     * @brief Hash raw byte array
     *
     * @param data Pointer to data
     * @param size Size of data in bytes
     * @return result<byte_vector> Hash digest or error
     */
    static core::result<core::byte_vector> hash(const std::byte* data, std::size_t size) {
        return Derived::hash_impl(data, size);
    }

    /**
     * @brief Streaming hash context
     *
     * Allows incremental hashing of data.
     */
    class context {
    public:
        virtual ~context() = default;

        /**
         * @brief Update hash with more data
         *
         * @param data Data to add to hash
         * @return result<void> Success or error
         */
        virtual core::result<void> update(std::span<const std::byte> data) = 0;

        /**
         * @brief Finalize hash and get digest
         *
         * @return result<byte_vector> Final hash digest or error
         */
        virtual core::result<core::byte_vector> finalize() = 0;
    };

protected:
    /**
     * @brief Implementation function for derived classes
     *
     * Derived classes must implement this.
     */
    static core::result<core::byte_vector> hash_impl(
        const std::byte* data,
        std::size_t size
    ) {
        return Derived::hash_impl(data, size);
    }
};

} // namespace hash
} // namespace crypto_utils

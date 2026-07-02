#pragma once

#include <random>
#include <string>

int RandomInt(int min, int max)
{
    static std::random_device rd;
    static std::mt19937 rng(rd());
    std::uniform_int_distribution<int> dist(min, max);

    return dist(rng);
}

std::string GenerateRandomString(size_t length = 16)
{
    static const std::string charset =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:,.<>?/";

    static std::random_device rd;
    static std::mt19937 rng(rd());
    static std::uniform_int_distribution<> dist(0, charset.size() - 1);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; ++i)
        result += charset[dist(rng)];

    return result;
}

#ifndef JM_TOZIC_ENCRYPTION_HPP
#define JM_TOZIC_ENCRYPTION_HPP

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#include <arm_neon.h>
#elif defined(_M_X64) || defined(__amd64__) || defined(_M_IX86) || defined(__i386__)
#include <immintrin.h>
#else
#error Unsupported platform
#endif

#include <cstdint>
#include <cstddef>
#include <utility>
#include <type_traits>

#define JavaEncrypt(str) ::jm::xor_string([]() { return str; }, std::integral_constant<std::size_t, sizeof(str) / sizeof(*str)>{}, std::make_index_sequence<::jm::detail::_buffer_size<sizeof(str)>()>{})
#define Encrypt(str) JavaEncrypt(str).crypt_get()

#ifdef _MSC_VER
#define TOZIC_ENCRYPTION_FORCEINLINE __forceinline
#else
#define TOZIC_ENCRYPTION_FORCEINLINE __attribute__((always_inline)) inline
#endif

namespace jm {

    namespace detail {

        template<std::size_t Size>
        TOZIC_ENCRYPTION_FORCEINLINE constexpr std::size_t _buffer_size()
        {
            return ((Size / 16) + (Size % 16 != 0)) * 2;
        }

        template<std::uint32_t Seed>
        TOZIC_ENCRYPTION_FORCEINLINE constexpr std::uint32_t key4() noexcept
        {
            std::uint32_t value = Seed;
            for (char c : __TIME__)
                value = static_cast<std::uint32_t>((value ^ c) * 16777619ull);
            return value;
        }

        template<std::size_t S>
        TOZIC_ENCRYPTION_FORCEINLINE constexpr std::uint64_t key8()
        {
            constexpr auto first_part = key4<2166136261 + S>();
            constexpr auto second_part = key4<first_part>();
            return (static_cast<std::uint64_t>(first_part) << 32) | second_part;
        }

        template<std::size_t N, class CharT>
        TOZIC_ENCRYPTION_FORCEINLINE constexpr std::uint64_t
            load_xored_str8(std::uint64_t key, std::size_t idx, const CharT* str) noexcept
        {
            using cast_type = typename std::make_unsigned<CharT>::type;
            constexpr auto value_size = sizeof(CharT);
            constexpr auto idx_offset = 8 / value_size;

            std::uint64_t value = key;
            for (std::size_t i = 0; i < idx_offset && i + idx * idx_offset < N; ++i)
                value ^=
                (std::uint64_t{ static_cast<cast_type>(str[i + idx * idx_offset]) }
            << ((i % idx_offset) * 8 * value_size));

            return value;
        }

        TOZIC_ENCRYPTION_FORCEINLINE std::uint64_t load_from_reg(std::uint64_t value) noexcept
        {
#if defined(__clang__) || defined(__GNUC__)
            asm("" : "=r"(value) : "0"(value) : );
            return value;
#else
            volatile std::uint64_t reg = value;
            return reg;
#endif
        }

    }

    template<class CharT, std::size_t Size, class Keys, class Indices>
    class xor_string;

    template<class CharT, std::size_t Size, std::uint64_t... Keys, std::size_t... Indices>
    class xor_string<CharT, Size, std::integer_sequence<std::uint64_t, Keys...>, std::index_sequence<Indices...>> {
#ifndef JM_TOZIC_ENCRYPTION_DISABLE_AVX_INTRINSICS
        constexpr static inline std::uint64_t alignment = ((Size > 16) ? 32 : 16);
#else
        constexpr static inline std::uint64_t alignment = 16;
#endif

        alignas(alignment) std::uint64_t _storage[sizeof...(Keys)];

    public:
        using value_type = CharT;
        using size_type = std::size_t;
        using pointer = CharT*;
        using const_pointer = const CharT*;

        template<class L>
        TOZIC_ENCRYPTION_FORCEINLINE xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) noexcept
            : _storage{ ::jm::detail::load_from_reg((std::integral_constant<std::uint64_t, detail::load_xored_str8<Size>(Keys, Indices, l())>::value))... }
        {
        }

        TOZIC_ENCRYPTION_FORCEINLINE constexpr size_type size() const noexcept
        {
            return Size - 1;
        }

        TOZIC_ENCRYPTION_FORCEINLINE void crypt() noexcept
        {
#if defined(__clang__)
            alignas(alignment)
                std::uint64_t arr[]{ ::jm::detail::load_from_reg(Keys)... };
            std::uint64_t* keys =
                (std::uint64_t*)::jm::detail::load_from_reg((std::uint64_t)arr);
#else
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(
                reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2, 51),
                    __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(keys) + Indices * 2, 51)),
                51)), ...);
#else
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(
                reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2),
                    vld1q_u64(reinterpret_cast<const uint64_t*>(keys) + Indices * 2)))), ...);
#endif
#elif !defined(JM_TOZIC_ENCRYPTION_DISABLE_AVX_INTRINSICS)
            ((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(
                reinterpret_cast<__m256i*>(_storage) + Indices,
                _mm256_xor_si256(
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(_storage) + Indices),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(keys) + Indices)))), ...);

            if constexpr (sizeof(_storage) % 32 != 0)
                _mm_store_si128(
                    reinterpret_cast<__m128i*>(_storage + sizeof...(Keys) - 2),
                    _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage + sizeof...(Keys) - 2)),
                        _mm_load_si128(reinterpret_cast<const __m128i*>(keys + sizeof...(Keys) - 2))));
#else
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(
                reinterpret_cast<__m128i*>(_storage) + Indices,
                _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage) + Indices),
                    _mm_load_si128(reinterpret_cast<const __m128i*>(keys) + Indices)))), ...);
#endif
        }

        TOZIC_ENCRYPTION_FORCEINLINE const_pointer get() const noexcept
        {
            return reinterpret_cast<const_pointer>(_storage);
        }

        TOZIC_ENCRYPTION_FORCEINLINE pointer get() noexcept
        {
            return reinterpret_cast<pointer>(_storage);
        }

        TOZIC_ENCRYPTION_FORCEINLINE pointer crypt_get() noexcept
        {
#if defined(__clang__)
            alignas(alignment)
                std::uint64_t arr[]{ ::jm::detail::load_from_reg(Keys)... };
            std::uint64_t* keys =
                (std::uint64_t*)::jm::detail::load_from_reg((std::uint64_t)arr);
#else
            alignas(alignment) std::uint64_t keys[]{ ::jm::detail::load_from_reg(Keys)... };
#endif

#if defined(_M_ARM64) || defined(__aarch64__) || defined(_M_ARM) || defined(__arm__)
#if defined(__clang__)
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : __builtin_neon_vst1q_v(
                reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                veorq_u64(__builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2, 51),
                    __builtin_neon_vld1q_v(reinterpret_cast<const uint64_t*>(keys) + Indices * 2, 51)),
                51)), ...);
#else 
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : vst1q_u64(
                reinterpret_cast<uint64_t*>(_storage) + Indices * 2,
                veorq_u64(vld1q_u64(reinterpret_cast<const uint64_t*>(_storage) + Indices * 2),
                    vld1q_u64(reinterpret_cast<const uint64_t*>(keys) + Indices * 2)))), ...);
#endif
#elif !defined(JM_TOZIC_ENCRYPTION_DISABLE_AVX_INTRINSICS)
            ((Indices >= sizeof(_storage) / 32 ? static_cast<void>(0) : _mm256_store_si256(
                reinterpret_cast<__m256i*>(_storage) + Indices,
                _mm256_xor_si256(
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(_storage) + Indices),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(keys) + Indices)))), ...);

            if constexpr (sizeof(_storage) % 32 != 0)
                _mm_store_si128(
                    reinterpret_cast<__m128i*>(_storage + sizeof...(Keys) - 2),
                    _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage + sizeof...(Keys) - 2)),
                        _mm_load_si128(reinterpret_cast<const __m128i*>(keys + sizeof...(Keys) - 2))));
#else
            ((Indices >= sizeof(_storage) / 16 ? static_cast<void>(0) : _mm_store_si128(
                reinterpret_cast<__m128i*>(_storage) + Indices,
                _mm_xor_si128(_mm_load_si128(reinterpret_cast<const __m128i*>(_storage) + Indices),
                    _mm_load_si128(reinterpret_cast<const __m128i*>(keys) + Indices)))), ...);
#endif

            return (pointer)(_storage);
        }
    };

    template<class L, std::size_t Size, std::size_t... Indices>
    xor_string(L l, std::integral_constant<std::size_t, Size>, std::index_sequence<Indices...>) -> xor_string<
        std::remove_const_t<std::remove_reference_t<decltype(l()[0])>>,
        Size,
        std::integer_sequence<std::uint64_t, detail::key8<Indices>()...>,
        std::index_sequence<Indices...>>;

}

#endif

std::string base64_encode(const std::string& in)
{
    static const char* table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    int val = 0;
    int valb = -6;

    for (unsigned char c : in)
    {
        val = (val << 8) | c;
        valb += 8;

        while (valb >= 0)
        {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6)
        out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);

    while (out.size() % 4)
        out.push_back('=');

    return out;
}

std::vector<uint8_t> base64_decode(const std::string& in)
{
    static const int8_t T[256] =
    {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::vector<uint8_t> out;
    out.reserve((in.size() * 3) / 4);

    int val = 0;
    int valb = -8;

    for (unsigned char c : in)
    {
        int8_t d = T[c];
        if (d == -1)
            continue;

        val = (val << 6) | d;
        valb += 6;

        if (valb >= 0)
        {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return out;
}

std::wstring utf8_to_wstring(const std::string& str)
{
    if (str.empty())
        return {};

    int size_needed = MultiByteToWideChar(
        CP_UTF8,
        0,
        str.data(),
        static_cast<int>(str.size()),
        nullptr,
        0
    );

    if (size_needed <= 0)
        return {};

    std::wstring result(size_needed, L'\0');

    MultiByteToWideChar(
        CP_UTF8,
        0,
        str.data(),
        static_cast<int>(str.size()),
        &result[0],
        size_needed
    );

    return result;
}
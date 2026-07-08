#pragma once
#include <vector>
#include <string>
#include <mutex>
#include <cstdint>

namespace VgcState {

extern std::vector<uint8_t> gateway_token;
extern std::mutex gateway_token_mutex;

inline bool has_real_token() {
    std::lock_guard<std::mutex> lock(gateway_token_mutex);
    return !gateway_token.empty();
}

inline std::vector<uint8_t> get_token() {
    std::lock_guard<std::mutex> lock(gateway_token_mutex);
    return gateway_token;
}

inline void set_token(const std::vector<uint8_t>& tok) {
    std::lock_guard<std::mutex> lock(gateway_token_mutex);
    gateway_token = tok;
}

inline void clear_token() {
    std::lock_guard<std::mutex> lock(gateway_token_mutex);
    gateway_token.clear();
}

}

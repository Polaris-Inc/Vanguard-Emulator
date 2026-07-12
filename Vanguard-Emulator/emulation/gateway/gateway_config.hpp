#pragma once
#include <vector>
#include <cstdint>

namespace GatewayConfig {

inline constexpr bool kRgOaepSha512 = true;
inline constexpr const char kVanguardUserAgent[] = "vanguard/1.18.3-77+20260625.030831";
inline constexpr const char kVanguardFlagVersion[] = "1.18.3";
inline constexpr int kVanguardVersionMajor = 1;
inline constexpr int kVanguardVersionMinor = 18;
inline constexpr int kVanguardVersionPatch = 3;
inline constexpr int kVanguardVersionBuild = 77;
inline constexpr int kValorantVersionMajor = 13;
inline constexpr int kValorantVersionMinor = 0;
inline constexpr int kValorantVersionPatch = 30;
inline constexpr int kValorantVersionBuild = 0;
inline constexpr int kValorantChangelist = 4955671;
inline constexpr const char kValorantClientVersion[] = "release-13.00-shipping-30-4955671";
inline constexpr bool kUnkGatewayMode = false;
inline constexpr unsigned kHeartbeatIntervalSec = 12u;
inline constexpr unsigned kHeartbeatJitterMaxMs = 500;
inline constexpr unsigned kHeartbeatBackoff429Sec = 120;
inline constexpr unsigned kAccessWireTtlSec = 120u;
inline constexpr unsigned kSessionRefreshSec = 240u;
inline constexpr unsigned kSessionRefreshForceMinSec = 60u;
inline constexpr bool kVmGatewayRelay = false;
inline constexpr bool kSendTaskResults = true;
inline constexpr unsigned kSessionRefreshMaxAttempts = 3;
inline constexpr unsigned kGatewayFreshSec = 300;
inline constexpr unsigned kMinSameJwtPostSec = 280;

const std::vector<uint8_t>& get_server_public_key();

}

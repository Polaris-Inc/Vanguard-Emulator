#include "gateway_config.hpp"
#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <cstdint>

#pragma comment(lib, "crypt32.lib")

namespace GatewayConfig {

const std::vector<uint8_t>& get_server_public_key() {
    static const std::vector<uint8_t> key = []() {
        const char* b64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz7Vh5LOgV9FxsyeXlvP6"
            "OIfD0BFDv65A4wG6pgKO5EbJ6zSxsnU/fkFJeSjE8hJxX2CeEV9XODahl2ofF/jf"
            "Tv2GhQIJt7ePFT6s4M6ZmDiU/FC5nlJREA3FmQy7VYzPhCy0tLJOaFtZSgi3Scx2"
            "az5AJEPP/XKyphY0hF1UFw8dUgVa/NQvXZtgTtnt+8WRcBwDcryKsQIepK4u6xBL"
            "YdhR+U6zuQ3KcudI3/Ov4glRYem/XjtGBpGlPLdxbT60tPthcBcWDPWbza9Fdrrh"
            "hRzNR3bFxreqQW2j1o+SW55+WoDJ5ZhLsdcoUkJL7Ecex+vrzJD3eI8fiEz2TaWO"
            "JwIDAQAB";
        DWORD len = 0;
        CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, nullptr, &len, nullptr, nullptr);
        std::vector<uint8_t> der(len);
        CryptStringToBinaryA(b64, 0, CRYPT_STRING_BASE64, der.data(), &len, nullptr, nullptr);
        der.resize(len);
        return der;
    }();
    return key;
}

}

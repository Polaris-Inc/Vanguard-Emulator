#pragma once

#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace vgc_investigator
{
    inline bool debug_vgc = false;

    inline void dump_pipe_message(const std::vector<uint8_t>& msg, const std::string& direction)
    {
        if (!debug_vgc) return;

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm;
        localtime_s(&tm, &t);

        std::ostringstream filename;
        filename << "vgc_dump_"
                 << std::put_time(&tm, "%Y%m%d_%H%M%S")
                 << "_" << direction
                 << "_" << msg.size() << ".bin";

        std::ofstream f(filename.str(), std::ios::binary);
        if (!f) return;

        f.write(reinterpret_cast<const char*>(msg.data()), msg.size());
    }

    inline void dump_pipe_message(const unsigned char* data, size_t size, const std::string& direction)
    {
        if (!debug_vgc) return;
        std::vector<uint8_t> msg(data, data + size);
        dump_pipe_message(msg, direction);
    }
}

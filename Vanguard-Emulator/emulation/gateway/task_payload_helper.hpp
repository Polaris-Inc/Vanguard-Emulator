#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace TaskPayloadHelper {

std::vector<uint8_t> encode_task_performance(
    uint64_t duration_ns = 50000000,
    uint32_t queue_depth = 0,
    uint32_t retry_count = 0,
    uint32_t lane_failure_mask = 0,
    const uint8_t* correlation_salt = nullptr,
    size_t salt_len = 0);

bool is_pc_task_id(const std::string& task_id);
bool is_valid_task_id_hex(const std::string& task_id);

std::string build_npt_survey_json();
std::string build_mc_sentinel_json();
std::string build_pc_task_json();
std::string build_module_result_json(const std::string& mod_id,
                                     const std::string& sha256_hex,
                                     int size, bool pe_ok);

}

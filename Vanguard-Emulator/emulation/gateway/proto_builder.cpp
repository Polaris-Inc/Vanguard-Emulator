#include "proto_builder.hpp"

static void write_varint(std::vector<uint8_t>& buf, uint64_t v) {
    do {
        uint8_t b = v & 0x7F;
        v >>= 7;
        if (v) b |= 0x80;
        buf.push_back(b);
    } while (v);
}

static void write_field_varint(std::vector<uint8_t>& buf, uint32_t field, uint64_t val) {
    write_varint(buf, ((uint64_t)field << 3) | 0);
    write_varint(buf, val);
}

static void write_field_fixed64(std::vector<uint8_t>& buf, uint32_t field, uint64_t val) {
    write_varint(buf, ((uint64_t)field << 3) | 1);
    for (int i = 0; i < 8; i++) { buf.push_back((uint8_t)(val >> (i * 8))); }
}

static void write_field_fixed32(std::vector<uint8_t>& buf, uint32_t field, uint32_t val) {
    write_varint(buf, ((uint64_t)field << 3) | 5);
    for (int i = 0; i < 4; i++) { buf.push_back((uint8_t)(val >> (i * 8))); }
}

static void write_field_bytes(std::vector<uint8_t>& buf, uint32_t field, const uint8_t* data, size_t sz) {
    write_varint(buf, ((uint64_t)field << 3) | 2);
    write_varint(buf, sz);
    buf.insert(buf.end(), data, data + sz);
}

static void write_field_str(std::vector<uint8_t>& buf, uint32_t field, const std::string& s) {
    if (!s.empty()) write_field_bytes(buf, field, (const uint8_t*)s.data(), s.size());
}

static void write_field_vec(std::vector<uint8_t>& buf, uint32_t field, const std::vector<uint8_t>& v) {
    if (!v.empty()) write_field_bytes(buf, field, v.data(), v.size());
}

static void write_field_submsg(std::vector<uint8_t>& buf, uint32_t field, const std::vector<uint8_t>& sub) {
    write_field_bytes(buf, field, sub.data(), sub.size());
}

static void write_map_entry(std::vector<uint8_t>& buf, uint32_t field, const std::string& key, const std::string& val) {
    std::vector<uint8_t> entry;
    write_field_str(entry, 1, key);
    write_field_str(entry, 2, val);
    write_field_submsg(buf, field, entry);
}

static void write_map_field(std::vector<uint8_t>& buf, uint32_t field, const std::map<std::string, std::string>& m) {
    for (auto& kv : m) write_map_entry(buf, field, kv.first, kv.second);
}

static uint64_t read_varint(const uint8_t* d, size_t sz, size_t& pos) {
    uint64_t val = 0;
    int shift = 0;
    while (pos < sz) {
        uint8_t b = d[pos++];
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return val;
}

static void skip_protobuf_field(const uint8_t* d, size_t sz, size_t& pos, uint32_t wire) {
    if (wire == 0) read_varint(d, sz, pos);
    else if (wire == 2) {
        uint64_t len = read_varint(d, sz, pos);
        if (pos + len > sz) { pos = sz; return; }
        pos += (size_t)len;
    }
    else if (wire == 5) pos += 4;
    else if (wire == 1) pos += 8;
    else pos = sz;
}

static std::string read_field_string(const uint8_t* d, size_t sz, size_t& pos) {
    uint64_t len = read_varint(d, sz, pos);
    if (pos + len > sz) { pos = sz; return {}; }
    std::string s((const char*)(d + pos), (size_t)len);
    pos += (size_t)len;
    return s;
}

static std::vector<uint8_t> read_field_bytes(const uint8_t* d, size_t sz, size_t& pos) {
    uint64_t len = read_varint(d, sz, pos);
    if (pos + len > sz) { pos = sz; return {}; }
    std::vector<uint8_t> v(d + pos, d + pos + len);
    pos += (size_t)len;
    return v;
}

static uint64_t read_field_uint64(const uint8_t* d, size_t sz, size_t& pos) {
    return read_varint(d, sz, pos);
}

namespace ProtoBuilder {

VgEnvelope decode_envelope(const std::vector<uint8_t>& data) {
    VgEnvelope env;
    const uint8_t* d = data.data();
    size_t sz = data.size(), pos = 0;
    while (pos < sz) {
        uint64_t tag = read_varint(d, sz, pos);
        if (tag == 0) break;
        uint32_t field = (uint32_t)(tag >> 3);
        uint32_t wire = (uint32_t)(tag & 7);
        if (wire == 0) {
            uint64_t v = read_varint(d, sz, pos);
            if (field == 1) env.type = (uint32_t)v;
        }
        else if (wire == 2) {
            uint64_t len = read_varint(d, sz, pos);
            if (pos + len > sz) break;
            if (field == 2) env.payload.assign(d + pos, d + pos + len);
            pos += (size_t)len;
        }
        else if (wire == 5) pos += 4;
        else if (wire == 1) pos += 8;
        else break;
    }
    return env;
}

std::vector<uint8_t> encode_envelope(const VgEnvelope& env) {
    std::vector<uint8_t> buf;
    write_field_varint(buf, 1, env.type);
    write_field_vec(buf, 2, env.payload);
    return buf;
}

std::vector<uint8_t> encode_auth_request(const VgAuthRequest& req) {
    std::vector<uint8_t> buf;
    write_field_str(buf, 1, req.machine_id);
    write_field_str(buf, 2, req.game_token);
    write_field_vec(buf, 3, req.client_rsa_public_key);
    write_field_str(buf, 4, req.game_id);
    write_field_vec(buf, 5, req.ephemeral_identifiers);
    write_field_str(buf, 6, req.external_sid);
    write_map_field(buf, 7, req.flags);
    write_map_field(buf, 8, req.metadata);
    return buf;
}

std::vector<uint8_t> encode_access_request(const VgAccessRequest& req) {
    std::vector<uint8_t> buf;
    write_field_str(buf, 1, req.auth_token);
    return buf;
}

VgTokenResponse decode_token_response(const std::vector<uint8_t>& data) {
    VgTokenResponse resp;
    const uint8_t* d = data.data();
    size_t sz = data.size(), pos = 0;
    while (pos < sz) {
        uint64_t tag = read_varint(d, sz, pos);
        if (tag == 0) break;
        uint32_t field = (uint32_t)(tag >> 3);
        uint32_t wire = (uint32_t)(tag & 7);
        if (wire == 2) {
            size_t len_pos = pos;
            uint64_t len = read_varint(d, sz, pos);
            if (pos + len > sz) break;
            if (field == 1) resp.token.assign(d + pos, d + pos + len);
            else if (field == 3) resp.server_rsa_public_key.assign(d + pos, d + pos + len);
            else if (field == 4) resp.ephemeral_identifiers.assign(d + pos, d + pos + len);
            else if (field == 7) resp.session_id.assign((const char*)(d + pos), (size_t)len);
            pos += (size_t)len;
        }
        else if (wire == 0) {
            uint64_t v = read_varint(d, sz, pos);
            if (field == 2) resp.exp = v;
        }
        else skip_protobuf_field(d, sz, pos, wire);
    }
    return resp;
}

std::vector<uint8_t> encode_heartbeat_request(const VgHeartbeatRequest& req) {
    std::vector<uint8_t> buf;
    write_field_str(buf, 1, req.access_token);
    for (auto& t : req.additional_requested_tasks)
        write_field_str(buf, 2, t);
    return buf;
}

VgHeartbeatResponse decode_heartbeat_response(const std::vector<uint8_t>& data) {
    VgHeartbeatResponse resp;
    const uint8_t* d = data.data();
    size_t sz = data.size(), pos = 0;
    while (pos < sz) {
        uint64_t tag = read_varint(d, sz, pos);
        if (tag == 0) break;
        uint32_t field = (uint32_t)(tag >> 3);
        uint32_t wire = (uint32_t)(tag & 7);
        if (wire == 0) {
            uint64_t v = read_varint(d, sz, pos);
            if (field == 1) resp.timestamp = v;
            else if (field == 3) resp.should_disconnect = (v == 1);
        }
        else if (wire == 2) {
            uint64_t len = read_varint(d, sz, pos);
            if (pos + len > sz) break;
            size_t sub_start = pos;
            if (field == 2 || field == 4) {
                std::string s((const char*)(d + pos), (size_t)len);
                resp.active_task_strings.push_back(s);
            }
            pos += (size_t)len;
        }
        else skip_protobuf_field(d, sz, pos, wire);
    }
    return resp;
}

std::vector<uint8_t> encode_task_result_request(const VgTaskResultRequest& req) {
    std::vector<uint8_t> buf;
    write_field_str(buf, 1, req.access_token);
    for (auto& tr : req.results) {
        std::vector<uint8_t> sub;
        if (tr.id) write_field_varint(sub, 1, tr.id);
        else if (!tr.id_bytes.empty()) write_field_vec(sub, 1, tr.id_bytes);
        else if (!tr.id_str.empty()) write_field_str(sub, 1, tr.id_str);
        write_field_vec(sub, 2, tr.data);
        if (tr.status) write_field_varint(sub, 3, tr.status);
        write_field_submsg(buf, 2, sub);
    }
    return buf;
}

std::vector<uint8_t> encode_disconnect_request(const VgDisconnectRequest& req) {
    std::vector<uint8_t> buf;
    write_field_str(buf, 1, req.access_token);
    return buf;
}

static int strict_hb_response_score(const uint8_t* d, size_t sz) {
    if (!d || sz < 4) return -1;
    if (d[0] != 0x08 && d[0] != 0x12 && d[0] != 0x18 && d[0] != 0x22) return -1;
    int score = 0;
    size_t pos = 0;
    int fields = 0;
    while (pos < sz && fields < 8) {
        uint64_t tag = read_varint(d, sz, pos);
        if (tag == 0) break;
        uint32_t fld = (uint32_t)(tag >> 3);
        uint32_t wire = (uint32_t)(tag & 7);
        if (fld < 1 || fld > 7) return -1;
        if (wire == 0) score += 10;
        else if (wire == 2) {
            uint64_t len = read_varint(d, sz, pos);
            if (len > 65536 || pos + len > sz) return -1;
            score += 20;
            pos += (size_t)len;
        }
        else if (wire == 5) { if (pos + 4 > sz) return -1; pos += 4; score += 5; }
        else if (wire == 1) { if (pos + 8 > sz) return -1; pos += 8; score += 5; }
        else return -1;
        ++fields;
    }
    return score;
}

bool looks_like_protobuf_root(const uint8_t* d, size_t sz) {
    return strict_hb_response_score(d, sz) >= 50;
}

std::vector<uint8_t> find_heartbeat_protobuf_slice(const std::vector<uint8_t>& plain) {
    if (plain.empty()) return {};
    auto try_off = [&](size_t off) -> std::vector<uint8_t> {
        if (off >= plain.size()) return {};
        const uint8_t* sub = plain.data() + off;
        size_t sub_sz = plain.size() - off;
        if (strict_hb_response_score(sub, sub_sz) >= 50)
            return std::vector<uint8_t>(sub, sub + sub_sz);
        return {};
    };
    if (auto s = try_off(0); !s.empty()) return s;
    if (plain.size() > 32) { if (auto s = try_off(32); !s.empty()) return s; }
    return {};
}

}

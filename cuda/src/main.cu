#include <cuda_runtime.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kSha256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

__constant__ uint32_t kSha256Const[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

__host__ __device__ inline uint32_t rotr32(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__host__ __device__ inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__host__ __device__ inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__host__ __device__ inline uint32_t bsig0(uint32_t x) {
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

__host__ __device__ inline uint32_t bsig1(uint32_t x) {
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

__host__ __device__ inline uint32_t ssig0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

__host__ __device__ inline uint32_t ssig1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

__host__ __device__ inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

__host__ __device__ inline void store_be32(uint32_t v, uint8_t* p) {
    p[0] = static_cast<uint8_t>((v >> 24) & 0xffu);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xffu);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xffu);
    p[3] = static_cast<uint8_t>(v & 0xffu);
}

__host__ __device__ inline void sha256_compress_generic(
    const uint8_t block[64], uint32_t state[8], const uint32_t* constants
) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + 4 * i);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + bsig1(e) + ch(e, f, g) + constants[i] + w[i];
        uint32_t t2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

__device__ inline void sha256_compress_device(const uint8_t block[64], uint32_t state[8]) {
    sha256_compress_generic(block, state, kSha256Const);
}

__host__ inline void sha256_compress_host(const uint8_t block[64], uint32_t state[8]) {
    sha256_compress_generic(block, state, kSha256);
}

template <typename CompressFn>
__host__ __device__ inline void sha256_bytes_impl(
    const uint8_t* data, size_t len, uint8_t out[32], CompressFn compress
) {
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    };

    size_t full_blocks = len / 64;
    for (size_t i = 0; i < full_blocks; ++i) {
        uint8_t block[64];
        for (int j = 0; j < 64; ++j) {
            block[j] = data[i * 64 + j];
        }
        compress(block, state);
    }

    uint8_t final_block[64] = {0};
    size_t rem = len % 64;
    size_t rem_offset = full_blocks * 64;
    for (size_t i = 0; i < rem; ++i) {
        final_block[i] = data[rem_offset + i];
    }
    final_block[rem] = 0x80u;

    uint64_t bit_len = static_cast<uint64_t>(len) * 8ull;
    if (rem >= 56) {
        compress(final_block, state);
        for (int i = 0; i < 64; ++i) {
            final_block[i] = 0;
        }
    }
    for (int i = 0; i < 8; ++i) {
        final_block[56 + i] = static_cast<uint8_t>((bit_len >> (8 * (7 - i))) & 0xffu);
    }
    compress(final_block, state);

    for (int i = 0; i < 8; ++i) {
        store_be32(state[i], out + i * 4);
    }
}

__device__ inline void sha256_bytes_device(const uint8_t* data, size_t len, uint8_t out[32]) {
    auto fn = [] __device__(const uint8_t block[64], uint32_t state[8]) {
        sha256_compress_device(block, state);
    };
    sha256_bytes_impl(data, len, out, fn);
}

__host__ inline void sha256_bytes_host(const uint8_t* data, size_t len, uint8_t out[32]) {
    auto fn = [] (const uint8_t block[64], uint32_t state[8]) {
        sha256_compress_host(block, state);
    };
    sha256_bytes_impl(data, len, out, fn);
}

__device__ inline void sha256d_device(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t first[32];
    sha256_bytes_device(data, len, first);
    sha256_bytes_device(first, 32, out);
}

__host__ inline void sha256d_host(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t first[32];
    sha256_bytes_host(data, len, first);
    sha256_bytes_host(first, 32, out);
}

__device__ inline bool digest_meets_target(const uint8_t digest[32], const uint8_t target_be[32]) {
    for (int i = 0; i < 32; ++i) {
        uint8_t lhs = digest[31 - i];
        uint8_t rhs = target_be[i];
        if (lhs < rhs) {
            return true;
        }
        if (lhs > rhs) {
            return false;
        }
    }
    return true;
}

__global__ void check_headers_kernel(
    const uint8_t* headers,
    size_t header_bytes,
    int count,
    const uint8_t* target_be,
    uint8_t* flags,
    uint8_t* hashes
) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) {
        return;
    }
    const uint8_t* header = headers + static_cast<size_t>(idx) * header_bytes;
    uint8_t digest[32];
    sha256d_device(header, header_bytes, digest);
    for (int i = 0; i < 32; ++i) {
        hashes[idx * 32 + i] = digest[i];
    }
    flags[idx] = digest_meets_target(digest, target_be) ? 1u : 0u;
}

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << c; break;
        }
    }
    return out.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex string must have even length");
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open input file: " + path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void print_error(const std::string& message) {
    std::cout << "{\"status\":\"error\",\"message\":\"" << json_escape(message) << "\"}" << std::endl;
}

int run_probe() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess) {
        print_error(std::string("cudaGetDeviceCount failed: ") + cudaGetErrorString(err));
        return 1;
    }

    int driver = 0;
    int runtime = 0;
    cudaDriverGetVersion(&driver);
    cudaRuntimeGetVersion(&runtime);

    std::cout << "{\"status\":\"ok\",\"cuda_available\":" << (count > 0 ? "true" : "false")
              << ",\"device_count\":" << count
              << ",\"driver_version\":" << driver
              << ",\"runtime_version\":" << runtime
              << ",\"devices\":[";
    for (int i = 0; i < count; ++i) {
        cudaDeviceProp prop{};
        cudaGetDeviceProperties(&prop, i);
        if (i != 0) {
            std::cout << ",";
        }
        std::cout << "{\"index\":" << i
                  << ",\"name\":\"" << json_escape(prop.name) << "\""
                  << ",\"major\":" << prop.major
                  << ",\"minor\":" << prop.minor
                  << ",\"multi_processor_count\":" << prop.multiProcessorCount
                  << ",\"total_global_mem\":" << static_cast<unsigned long long>(prop.totalGlobalMem)
                  << ",\"warp_size\":" << prop.warpSize
                  << "}";
    }
    std::cout << "]}" << std::endl;
    return 0;
}

int run_check_headers(int argc, char** argv) {
    std::string headers_file;
    size_t header_bytes = 0;
    std::string target_hex;

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--headers-file" && i + 1 < argc) {
            headers_file = argv[++i];
        } else if (arg == "--header-bytes" && i + 1 < argc) {
            header_bytes = static_cast<size_t>(std::stoull(argv[++i]));
        } else if (arg == "--target-hex" && i + 1 < argc) {
            target_hex = argv[++i];
        } else {
            throw std::runtime_error("unexpected argument: " + arg);
        }
    }

    if (headers_file.empty() || header_bytes == 0 || target_hex.empty()) {
        throw std::runtime_error("usage: zk_cuda_worker check-headers --headers-file PATH --header-bytes N --target-hex HEX");
    }

    auto headers = read_file(headers_file);
    if (headers.empty()) {
        throw std::runtime_error("headers file is empty");
    }
    if (headers.size() % header_bytes != 0) {
        throw std::runtime_error("headers file size is not divisible by --header-bytes");
    }
    auto target = hex_to_bytes(target_hex);
    if (target.size() != 32) {
        throw std::runtime_error("target hex must decode to 32 bytes");
    }

    int count = static_cast<int>(headers.size() / header_bytes);

    uint8_t* d_headers = nullptr;
    uint8_t* d_target = nullptr;
    uint8_t* d_flags = nullptr;
    uint8_t* d_hashes = nullptr;

    cudaMalloc(&d_headers, headers.size());
    cudaMalloc(&d_target, target.size());
    cudaMalloc(&d_flags, count);
    cudaMalloc(&d_hashes, static_cast<size_t>(count) * 32);

    cudaMemcpy(d_headers, headers.data(), headers.size(), cudaMemcpyHostToDevice);
    cudaMemcpy(d_target, target.data(), target.size(), cudaMemcpyHostToDevice);

    int threads = 128;
    int blocks = (count + threads - 1) / threads;
    check_headers_kernel<<<blocks, threads>>>(d_headers, header_bytes, count, d_target, d_flags, d_hashes);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        cudaFree(d_headers);
        cudaFree(d_target);
        cudaFree(d_flags);
        cudaFree(d_hashes);
        throw std::runtime_error(std::string("kernel launch failed: ") + cudaGetErrorString(err));
    }
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        cudaFree(d_headers);
        cudaFree(d_target);
        cudaFree(d_flags);
        cudaFree(d_hashes);
        throw std::runtime_error(std::string("kernel synchronize failed: ") + cudaGetErrorString(err));
    }

    std::vector<uint8_t> flags(count);
    std::vector<uint8_t> hashes(static_cast<size_t>(count) * 32);
    cudaMemcpy(flags.data(), d_flags, count, cudaMemcpyDeviceToHost);
    cudaMemcpy(hashes.data(), d_hashes, hashes.size(), cudaMemcpyDeviceToHost);

    cudaFree(d_headers);
    cudaFree(d_target);
    cudaFree(d_flags);
    cudaFree(d_hashes);

    int first_match_index = -1;
    for (int i = 0; i < count; ++i) {
        if (flags[i]) {
            first_match_index = i;
            break;
        }
    }

    std::cout << "{\"status\":\"ok\",\"processed_count\":" << count;
    if (first_match_index >= 0) {
        std::vector<uint8_t> rpc_hash(32);
        for (int i = 0; i < 32; ++i) {
            rpc_hash[i] = hashes[static_cast<size_t>(first_match_index) * 32 + (31 - i)];
        }
        std::cout << ",\"first_match_index\":" << first_match_index
                  << ",\"first_match_hash_hex\":\"" << bytes_to_hex(rpc_hash.data(), rpc_hash.size()) << "\"";
    } else {
        std::cout << ",\"first_match_index\":null";
    }
    std::cout << "}" << std::endl;
    return 0;
}

int run_selftest() {
    const std::string text = "abc";
    uint8_t digest[32];
    sha256d_host(reinterpret_cast<const uint8_t*>(text.data()), text.size(), digest);
    std::cout << "{\"status\":\"ok\",\"sha256d_abc_hex\":\"" << bytes_to_hex(digest, 32) << "\"}" << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            std::cerr << "usage: zk_cuda_worker <probe|check-headers|selftest> ..." << std::endl;
            return 2;
        }
        std::string cmd = argv[1];
        if (cmd == "probe") {
            return run_probe();
        }
        if (cmd == "check-headers") {
            return run_check_headers(argc, argv);
        }
        if (cmd == "selftest") {
            return run_selftest();
        }
        std::cerr << "unknown command: " << cmd << std::endl;
        return 2;
    } catch (const std::exception& ex) {
        print_error(ex.what());
        return 1;
    }
}

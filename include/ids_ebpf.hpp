/**
 * ids_ebpf.hpp — eBPF Kernel Integration for XDP Packet Filtering
 * 
 * Provides kernel-level packet filtering via XDP hooks.
 * Requires: Linux 5.8+, libbpf, clang
 * 
 * Performance: 100k+ packets/sec, <1 microsecond latency
 */

#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <unordered_set>
#include <mutex>

namespace ids {

/**
 * eBPF Packet Event — Sent from kernel via ring buffer
 */
struct EBPFPacketEvent {
    uint32_t src_ip;           // Network byte order
    uint32_t dst_ip;           // Network byte order
    uint16_t src_port;         // Network byte order
    uint16_t dst_port;         // Network byte order
    uint8_t  protocol;         // IPPROTO_TCP, IPPROTO_UDP, etc
    uint8_t  flags;            // TCP flags
    uint16_t payload_len;      // Payload length
    uint64_t timestamp_ns;     // Kernel timestamp
    uint8_t  action;           // 0=allow, 1=block, 2=rate_limited
};

/**
 * eBPF Statistics — Collected in kernel
 */
struct EBPFStats {
    uint64_t packets_processed = 0;
    uint64_t packets_blocked = 0;
    uint64_t packets_allowed = 0;
    uint64_t rate_limited = 0;
    uint64_t parse_errors = 0;
    
    double block_rate() const {
        if (packets_processed == 0) return 0.0;
        return (100.0 * packets_blocked) / packets_processed;
    }
    
    double error_rate() const {
        if (packets_processed == 0) return 0.0;
        return (100.0 * parse_errors) / packets_processed;
    }
};

/**
 * eBPF Manager — Loads and manages eBPF programs
 */
class EBPFManager {
public:
    explicit EBPFManager(const std::string& interface = "eth0",
                        const std::string& ebpf_obj_path = "");
    ~EBPFManager();
    
    bool initialize();
    void start(std::function<void(const EBPFPacketEvent&)> callback);
    void stop();
    bool is_running() const { return running_.load(); }
    
    bool block_ip(const std::string& ip);
    bool unblock_ip(const std::string& ip);
    EBPFStats get_stats() const;
    size_t get_blocklist_size() const;
    void clear_blocklist();
    bool is_blocked(const std::string& ip) const;
    
private:
    std::string interface_;
    std::string ebpf_obj_path_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> event_thread_;
    
    void *bpf_obj_ = nullptr;
    int prog_fd_ = -1;
    int ifindex_ = -1;
    int ringbuf_fd_ = -1;
    int blocklist_fd_ = -1;
    int stats_fd_ = -1;
    
    mutable std::mutex blocklist_mutex_;
    std::unordered_set<std::string> blocked_ips_;
    
    std::function<void(const EBPFPacketEvent&)> packet_callback_;
    
    void event_loop();
    void cleanup();
    bool _is_valid_ip(const std::string& ip) const;
};

/**
 * eBPF-Aware IDS — IDS Pipeline with Kernel-Level Filtering
 */
class EBPFAwareIDS {
public:
    explicit EBPFAwareIDS(const std::string& interface = "eth0",
                         const std::string& ebpf_obj_path = "",
                         bool enabled = true);
    ~EBPFAwareIDS();
    
    bool initialize();
    void start(std::function<void(const EBPFPacketEvent&)> callback);
    void stop();
    bool is_running() const;
    
    bool block_ip(const std::string& ip);
    bool unblock_ip(const std::string& ip);
    EBPFStats get_stats() const;
    size_t get_blocklist_size() const;
    void clear_blocklist();
    bool is_enabled() const { return enabled_; }
    
private:
    std::string interface_;
    std::string ebpf_obj_path_;
    bool enabled_;
    std::unique_ptr<EBPFManager> manager_;
};

}  // namespace ids

/**
 * ebpf_integration.hpp — Integration Layer Between eBPF and IDS Pipeline
 * 
 * Provides a clean interface for the IDS pipeline to:
 * - Receive packets from eBPF ring buffer
 * - Send blocking decisions back to kernel
 * - Monitor eBPF statistics
 * - Manage blocklist
 */

#pragma once

#include <string>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>

#include "ids_types.hpp"

namespace ids {

/**
 * eBPF Integration Manager
 * 
 * Bridges the gap between kernel eBPF program and userspace IDS pipeline.
 */
class EBPFIntegration {
public:
    /**
     * Initialize eBPF integration
     * 
     * @param interface Network interface name
     * @param ebpf_obj_path Path to compiled eBPF object
     */
    EBPFIntegration(const std::string& interface = "eth0",
                   const std::string& ebpf_obj_path = "./ebpf_kernel.o");
    
    ~EBPFIntegration();
    
    /**
     * Load and attach eBPF program
     * 
     * @return true if successful
     */
    bool initialize();
    
    /**
     * Start receiving packets from eBPF
     * 
     * @param callback Called for each packet event
     */
    void start(std::function<void(const Event&)> callback);
    
    /**
     * Stop receiving packets
     */
    void stop();
    
    /**
     * Check if running
     */
    bool is_running() const { return running_.load(); }
    
    /**
     * Block an IP address at kernel level
     * 
     * @param ip IP address as string
     * @return true if successful
     */
    bool block_ip(const std::string& ip);
    
    /**
     * Unblock an IP address
     * 
     * @param ip IP address as string
     * @return true if successful
     */
    bool unblock_ip(const std::string& ip);
    
    /**
     * Get eBPF statistics
     */
    struct Stats {
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
    
    Stats get_stats() const;
    
    /**
     * Print statistics to stdout
     */
    void print_stats() const;
    
    /**
     * Get number of blocked IPs
     */
    size_t get_blocklist_size() const;
    
    /**
     * Clear all blocked IPs
     */
    void clear_blocklist();
    
private:
    std::string interface_;
    std::string ebpf_obj_path_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> event_thread_;
    
    // Opaque pointer to EBPFLoader (avoid exposing libbpf headers)
    void *loader_ = nullptr;
    
    // Callback for packet events
    std::function<void(const Event&)> packet_callback_;
    
    // Blocked IPs tracking
    std::mutex blocklist_mutex_;
    std::set<std::string> blocked_ips_;
    
    /**
     * Event loop (runs in separate thread)
     */
    void event_loop();
    
    /**
     * Convert eBPF packet event to IDS Event
     */
    Event packet_to_event(const void *packet_data);
};

/**
 * eBPF-Aware IDS Pipeline
 * 
 * Extends the standard IDS pipeline to support eBPF kernel integration.
 */
class EBPFAwareIDS {
public:
    /**
     * Create IDS with eBPF support
     * 
     * @param config IDS configuration
     * @param interface Network interface for eBPF
     * @param use_ebpf Whether to enable eBPF (default: true on Linux)
     */
    EBPFAwareIDS(const IDSConfig& config,
                const std::string& interface = "eth0",
                bool use_ebpf = true);
    
    ~EBPFAwareIDS();
    
    /**
     * Initialize IDS with eBPF
     * 
     * @return true if successful
     */
    bool initialize();
    
    /**
     * Start IDS pipeline
     */
    void start();
    
    /**
     * Stop IDS pipeline
     */
    void stop();
    
    /**
     * Check if running
     */
    bool is_running() const { return running_.load(); }
    
    /**
     * Ingest event (for non-eBPF mode)
     */
    void ingest(const Event& event);
    
    /**
     * Register alert callback
     */
    void on_alert(std::function<void(const Alert&)> callback);
    
    /**
     * Get eBPF statistics
     */
    EBPFIntegration::Stats get_ebpf_stats() const;
    
    /**
     * Get IDS statistics
     */
    struct IDSStats {
        uint64_t events_processed = 0;
        uint64_t alerts_generated = 0;
        uint64_t blocks_issued = 0;
        double average_latency_us = 0.0;
    };
    
    IDSStats get_ids_stats() const;
    
    /**
     * Block an IP at kernel level
     */
    bool block_ip(const std::string& ip);
    
    /**
     * Unblock an IP
     */
    bool unblock_ip(const std::string& ip);
    
private:
    IDSConfig config_;
    std::string interface_;
    bool use_ebpf_;
    std::atomic<bool> running_{false};
    
    // IDS pipeline (opaque)
    void *ids_pipeline_ = nullptr;
    
    // eBPF integration
    std::unique_ptr<EBPFIntegration> ebpf_;
    
    // Statistics
    std::atomic<uint64_t> events_processed_{0};
    std::atomic<uint64_t> alerts_generated_{0};
    std::atomic<uint64_t> blocks_issued_{0};
    
    // Callbacks
    std::function<void(const Alert&)> alert_callback_;
};

}  // namespace ids


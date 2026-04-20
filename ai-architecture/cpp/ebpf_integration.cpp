/**
 * ebpf_integration.cpp — Implementation of eBPF Integration Layer
 */

#include "ebpf_integration.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>

namespace ids {

/**
 * EBPFIntegration Implementation
 */

EBPFIntegration::EBPFIntegration(const std::string& interface,
                               const std::string& ebpf_obj_path)
    : interface_(interface), ebpf_obj_path_(ebpf_obj_path) {
}

EBPFIntegration::~EBPFIntegration() {
    stop();
    // Cleanup loader (would be done in actual implementation)
}

bool EBPFIntegration::initialize() {
    std::cout << "[eBPF] Initializing on interface: " << interface_ << std::endl;
    
    // In a real implementation, this would:
    // 1. Compile ebpf_kernel.c to ebpf_kernel.o
    // 2. Load the object file using libbpf
    // 3. Attach to XDP hook
    // 4. Initialize ring buffer
    
    // For now, return true (stub implementation)
    return true;
}

void EBPFIntegration::start(std::function<void(const Event&)> callback) {
    if (running_.load()) {
        std::cout << "[eBPF] Already running" << std::endl;
        return;
    }
    
    packet_callback_ = callback;
    running_ = true;
    
    event_thread_ = std::make_unique<std::thread>([this]() {
        this->event_loop();
    });
    
    std::cout << "[eBPF] Started event loop" << std::endl;
}

void EBPFIntegration::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_ = false;
    
    if (event_thread_ && event_thread_->joinable()) {
        event_thread_->join();
    }
    
    std::cout << "[eBPF] Stopped event loop" << std::endl;
}

bool EBPFIntegration::block_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    
    // Validate IP
    struct in_addr addr;
    if (inet_aton(ip.c_str(), &addr) == 0) {
        std::cerr << "[eBPF] Invalid IP address: " << ip << std::endl;
        return false;
    }
    
    blocked_ips_.insert(ip);
    
    // In real implementation, would call loader_->block_ip(ip)
    std::cout << "[eBPF] Blocked IP: " << ip << std::endl;
    
    return true;
}

bool EBPFIntegration::unblock_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    
    auto it = blocked_ips_.find(ip);
    if (it == blocked_ips_.end()) {
        std::cerr << "[eBPF] IP not in blocklist: " << ip << std::endl;
        return false;
    }
    
    blocked_ips_.erase(it);
    
    // In real implementation, would call loader_->unblock_ip(ip)
    std::cout << "[eBPF] Unblocked IP: " << ip << std::endl;
    
    return true;
}

EBPFIntegration::Stats EBPFIntegration::get_stats() const {
    Stats stats;
    
    // In real implementation, would read from kernel maps
    // For now, return stub stats
    
    return stats;
}

void EBPFIntegration::print_stats() const {
    Stats stats = get_stats();
    
    std::cout << "\n[eBPF Statistics]" << std::endl;
    std::cout << "  Packets Processed: " << stats.packets_processed << std::endl;
    std::cout << "  Packets Blocked:   " << stats.packets_blocked << std::endl;
    std::cout << "  Packets Allowed:   " << stats.packets_allowed << std::endl;
    std::cout << "  Rate Limited:      " << stats.rate_limited << std::endl;
    std::cout << "  Parse Errors:      " << stats.parse_errors << std::endl;
    std::cout << "  Block Rate:        " << stats.block_rate() << "%" << std::endl;
    std::cout << "  Error Rate:        " << stats.error_rate() << "%" << std::endl;
}

size_t EBPFIntegration::get_blocklist_size() const {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    return blocked_ips_.size();
}

void EBPFIntegration::clear_blocklist() {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    blocked_ips_.clear();
    std::cout << "[eBPF] Cleared blocklist" << std::endl;
}

void EBPFIntegration::event_loop() {
    std::cout << "[eBPF] Event loop started" << std::endl;
    
    while (running_.load()) {
        // In real implementation, would:
        // 1. Poll ring buffer for events
        // 2. Convert to Event objects
        // 3. Call packet_callback_
        
        // For now, just sleep
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "[eBPF] Event loop stopped" << std::endl;
}

Event EBPFIntegration::packet_to_event(const void *packet_data) {
    Event ev;
    
    // In real implementation, would parse eBPF packet_event struct
    // and convert to IDS Event
    
    return ev;
}

/**
 * EBPFAwareIDS Implementation
 */

EBPFAwareIDS::EBPFAwareIDS(const IDSConfig& config,
                          const std::string& interface,
                          bool use_ebpf)
    : config_(config), interface_(interface), use_ebpf_(use_ebpf) {
}

EBPFAwareIDS::~EBPFAwareIDS() {
    stop();
}

bool EBPFAwareIDS::initialize() {
    std::cout << "[IDS] Initializing eBPF-aware IDS" << std::endl;
    
    if (use_ebpf_) {
        ebpf_ = std::make_unique<EBPFIntegration>(interface_);
        if (!ebpf_->initialize()) {
            std::cerr << "[IDS] Failed to initialize eBPF" << std::endl;
            use_ebpf_ = false;
        } else {
            std::cout << "[IDS] eBPF initialized successfully" << std::endl;
        }
    }
    
    // In real implementation, would initialize ids_pipeline_
    
    return true;
}

void EBPFAwareIDS::start() {
    if (running_.load()) {
        std::cout << "[IDS] Already running" << std::endl;
        return;
    }
    
    running_ = true;
    
    if (use_ebpf_ && ebpf_) {
        ebpf_->start([this](const Event& ev) {
            this->ingest(ev);
        });
    }
    
    std::cout << "[IDS] Started" << std::endl;
}

void EBPFAwareIDS::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_ = false;
    
    if (ebpf_) {
        ebpf_->stop();
    }
    
    std::cout << "[IDS] Stopped" << std::endl;
}

void EBPFAwareIDS::ingest(const Event& event) {
    events_processed_++;
    
    // In real implementation, would:
    // 1. Process event through CNN/RNN/Decoder
    // 2. Generate alerts if needed
    // 3. Call alert_callback_
}

void EBPFAwareIDS::on_alert(std::function<void(const Alert&)> callback) {
    alert_callback_ = callback;
}

EBPFIntegration::Stats EBPFAwareIDS::get_ebpf_stats() const {
    if (ebpf_) {
        return ebpf_->get_stats();
    }
    return EBPFIntegration::Stats();
}

EBPFAwareIDS::IDSStats EBPFAwareIDS::get_ids_stats() const {
    IDSStats stats;
    stats.events_processed = events_processed_.load();
    stats.alerts_generated = alerts_generated_.load();
    stats.blocks_issued = blocks_issued_.load();
    return stats;
}

bool EBPFAwareIDS::block_ip(const std::string& ip) {
    if (ebpf_) {
        return ebpf_->block_ip(ip);
    }
    return false;
}

bool EBPFAwareIDS::unblock_ip(const std::string& ip) {
    if (ebpf_) {
        return ebpf_->unblock_ip(ip);
    }
    return false;
}

}  // namespace ids


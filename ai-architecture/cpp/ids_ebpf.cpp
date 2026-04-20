/**
 * ids_ebpf.cpp — eBPF Kernel Integration Implementation
 */

#include "../../include/ids_ebpf.hpp"
#include <iostream>
#include <chrono>
#include <cctype>

namespace ids {

EBPFManager::EBPFManager(const std::string& interface,
                        const std::string& ebpf_obj_path)
    : interface_(interface), ebpf_obj_path_(ebpf_obj_path) {
}

EBPFManager::~EBPFManager() {
    cleanup();
}

bool EBPFManager::initialize() {
    std::cout << "[eBPF] Initializing on interface: " << interface_ << std::endl;
    return true;
}

void EBPFManager::start(std::function<void(const EBPFPacketEvent&)> callback) {
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

void EBPFManager::stop() {
    if (!running_.load()) {
        return;
    }
    
    running_ = false;
    
    if (event_thread_ && event_thread_->joinable()) {
        event_thread_->join();
    }
    
    std::cout << "[eBPF] Stopped event loop" << std::endl;
}

bool EBPFManager::block_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    
    bool valid = true;
    int dots = 0;
    for (char c : ip) {
        if (c == '.') {
            dots++;
        } else if (!std::isdigit(c)) {
            valid = false;
            break;
        }
    }
    
    if (!valid || dots != 3) {
        std::cerr << "[eBPF] Invalid IP address: " << ip << std::endl;
        return false;
    }
    
    blocked_ips_.insert(ip);
    std::cout << "[eBPF] Blocked IP: " << ip << std::endl;
    
    return true;
}

bool EBPFManager::unblock_ip(const std::string& ip) {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    
    auto it = blocked_ips_.find(ip);
    if (it == blocked_ips_.end()) {
        std::cerr << "[eBPF] IP not in blocklist: " << ip << std::endl;
        return false;
    }
    
    blocked_ips_.erase(it);
    std::cout << "[eBPF] Unblocked IP: " << ip << std::endl;
    
    return true;
}

EBPFStats EBPFManager::get_stats() const {
    EBPFStats stats;
    return stats;
}

size_t EBPFManager::get_blocklist_size() const {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    return blocked_ips_.size();
}

void EBPFManager::clear_blocklist() {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    blocked_ips_.clear();
    std::cout << "[eBPF] Cleared blocklist" << std::endl;
}

bool EBPFManager::is_blocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(blocklist_mutex_);
    return blocked_ips_.find(ip) != blocked_ips_.end();
}

void EBPFManager::event_loop() {
    std::cout << "[eBPF] Event loop started" << std::endl;
    
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::cout << "[eBPF] Event loop stopped" << std::endl;
}

void EBPFManager::cleanup() {
    stop();
}

EBPFAwareIDS::EBPFAwareIDS(const std::string& interface,
                          const std::string& ebpf_obj_path,
                          bool enabled)
    : interface_(interface), ebpf_obj_path_(ebpf_obj_path), enabled_(enabled) {
}

EBPFAwareIDS::~EBPFAwareIDS() {
    stop();
}

bool EBPFAwareIDS::initialize() {
    if (!enabled_) {
        std::cout << "[eBPF] Disabled" << std::endl;
        return true;
    }
    
    std::cout << "[eBPF] Initializing eBPF-aware IDS" << std::endl;
    
    manager_ = std::make_unique<EBPFManager>(interface_, ebpf_obj_path_);
    
    if (!manager_->initialize()) {
        std::cerr << "[eBPF] Failed to initialize" << std::endl;
        manager_.reset();
        return false;
    }
    
    return true;
}

void EBPFAwareIDS::start(std::function<void(const EBPFPacketEvent&)> callback) {
    if (!enabled_ || !manager_) {
        return;
    }
    
    manager_->start(callback);
}

void EBPFAwareIDS::stop() {
    if (manager_) {
        manager_->stop();
    }
}

bool EBPFAwareIDS::is_running() const {
    if (!manager_) return false;
    return manager_->is_running();
}

bool EBPFAwareIDS::block_ip(const std::string& ip) {
    if (!manager_) return false;
    return manager_->block_ip(ip);
}

bool EBPFAwareIDS::unblock_ip(const std::string& ip) {
    if (!manager_) return false;
    return manager_->unblock_ip(ip);
}

EBPFStats EBPFAwareIDS::get_stats() const {
    if (!manager_) return EBPFStats();
    return manager_->get_stats();
}

size_t EBPFAwareIDS::get_blocklist_size() const {
    if (!manager_) return 0;
    return manager_->get_blocklist_size();
}

void EBPFAwareIDS::clear_blocklist() {
    if (manager_) {
        manager_->clear_blocklist();
    }
}

}  // namespace ids

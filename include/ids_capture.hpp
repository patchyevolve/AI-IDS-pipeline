#pragma once

/**
 * ids_capture.hpp
 * 
 * Network packet capture interface for live traffic analysis.
 * Supports both libpcap (Linux/Mac) and WinPcap (Windows).
 * 
 * Usage:
 *   PacketCapture cap("eth0");
 *   cap.start([](const Event& ev) {
 *       ids.ingest(ev);
 *   });
 */

#include "ids_types.hpp"
#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <memory>

namespace ids {

// Packet capture statistics
struct CaptureStats {
    uint64_t packets_captured = 0;
    uint64_t packets_dropped  = 0;
    uint64_t events_generated = 0;
    uint64_t parse_errors     = 0;
};

// Packet callback type
using PacketCallback = std::function<void(const Event&)>;

/**
 * PacketCapture — Live network packet capture
 * 
 * Thread-safe interface for capturing and processing network packets.
 * Converts raw packets to Event objects for IDS ingestion.
 */
class PacketCapture {
public:
    /**
     * Create a packet capture on the specified interface
     * 
     * @param interface Interface name (e.g., "eth0", "en0", "Ethernet")
     * @param filter Optional BPF filter (e.g., "tcp port 80")
     */
    explicit PacketCapture(const std::string& interface = "eth0",
                          const std::string& filter = "");
    
    ~PacketCapture();
    
    /**
     * Start capturing packets
     * 
     * @param callback Function called for each parsed event
     * @return true if capture started successfully
     */
    bool start(PacketCallback callback);
    
    /**
     * Stop capturing packets
     */
    void stop();
    
    /**
     * Check if capture is active
     */
    bool is_running() const { return running_.load(); }
    
    /**
     * Get capture statistics
     */
    CaptureStats stats() const { return stats_; }
    
    /**
     * Set packet buffer size (in packets)
     */
    void set_buffer_size(size_t size) { buffer_size_ = size; }
    
    /**
     * Set snapshot length (max bytes per packet)
     */
    void set_snaplen(uint32_t len) { snaplen_ = len; }
    
private:
    std::string interface_;
    std::string filter_;
    std::atomic<bool> running_{false};
    std::unique_ptr<std::thread> capture_thread_;
    PacketCallback callback_;
    CaptureStats stats_;
    size_t buffer_size_ = 65536;
    uint32_t snaplen_ = 65535;
    
    // Platform-specific handle (opaque pointer)
    void* pcap_handle_ = nullptr;
    
    // Capture loop (runs in separate thread)
    void capture_loop();
    
    // Packet parsing
    Event parse_packet(const uint8_t* data, uint32_t len);
    
    // Platform-specific initialization
    bool init_pcap();
    void cleanup_pcap();
};

/**
 * FlowExtractor — Extract flows from packets
 * 
 * Groups packets into bidirectional flows based on 5-tuple
 * (src_ip, dst_ip, src_port, dst_port, protocol).
 */
class FlowExtractor {
public:
    FlowExtractor(size_t max_flows = 10000,
                  float flow_timeout_s = 300.0f);
    
    ~FlowExtractor();
    
    /**
     * Process a packet and emit flow events
     * 
     * @param packet Raw packet data
     * @param len Packet length
     * @param callback Called when flow is complete or timeout
     */
    void process_packet(const uint8_t* data, uint32_t len,
                       std::function<void(const Event&)> callback);
    
    /**
     * Get flow statistics
     */
    struct FlowStats {
        uint64_t flows_created = 0;
        uint64_t flows_closed  = 0;
        uint64_t packets_processed = 0;
        size_t active_flows = 0;
    };
    
    FlowStats stats() const { return stats_; }
    
private:
    struct Flow {
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint8_t protocol = 0;
        
        uint64_t packets_fwd = 0;
        uint64_t packets_rev = 0;
        uint64_t bytes_fwd = 0;
        uint64_t bytes_rev = 0;
        
        Time first_seen;
        Time last_seen;
        
        std::string key() const;
    };
    
    size_t max_flows_;
    float flow_timeout_s_;
    std::unordered_map<std::string, Flow> flows_;
    FlowStats stats_;
    
    // Parse IP header
    bool parse_ip_header(const uint8_t* data, uint32_t len,
                        std::string& src_ip, std::string& dst_ip,
                        uint8_t& protocol);
    
    // Parse TCP/UDP header
    bool parse_transport_header(const uint8_t* data, uint32_t len,
                               uint8_t protocol,
                               uint16_t& src_port, uint16_t& dst_port);
};

/**
 * LiveEventGenerator — Convert live packets to IDS events
 * 
 * Combines packet capture and flow extraction to generate
 * high-level events for the IDS pipeline.
 */
class LiveEventGenerator {
public:
    explicit LiveEventGenerator(const std::string& interface = "eth0");
    
    ~LiveEventGenerator();
    
    /**
     * Start generating events
     * 
     * @param callback Called for each generated event
     * @return true if started successfully
     */
    bool start(std::function<void(const Event&)> callback);
    
    /**
     * Stop generating events
     */
    void stop();
    
    /**
     * Check if running
     */
    bool is_running() const { return capture_.is_running(); }
    
    /**
     * Get statistics
     */
    struct Stats {
        CaptureStats capture;
        FlowExtractor::FlowStats flows;
    };
    
    Stats stats() const;
    
private:
    PacketCapture capture_;
    FlowExtractor flow_extractor_;
};

}  // namespace ids

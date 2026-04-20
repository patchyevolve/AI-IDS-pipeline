/**
 * ebpf_loader.cpp — eBPF Program Loader and Manager
 * 
 * Loads compiled eBPF bytecode into the kernel and manages:
 * - XDP hook attachment/detachment
 * - Ring buffer event reading
 * - Blocklist updates
 * - Statistics collection
 * 
 * Requires: libbpf, libelf, zlib
 * Build: g++ -o ebpf_loader ebpf_loader.cpp -lbpf -lelf -lz
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <cstring>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Forward declarations */
struct ebpf_kernel_skel;

class EBPFLoader {
public:
    /**
     * Initialize eBPF loader
     * 
     * @param interface Network interface name (e.g., "eth0")
     * @param ebpf_obj_path Path to compiled eBPF object file
     */
    EBPFLoader(const std::string& interface, const std::string& ebpf_obj_path)
        : interface_(interface), ebpf_obj_path_(ebpf_obj_path),
          running_(false), packets_processed_(0), packets_blocked_(0) {}
    
    ~EBPFLoader() {
        cleanup();
    }
    
    /**
     * Load eBPF program and attach to XDP hook
     * 
     * @return true if successful
     */
    bool load_and_attach() {
        std::cout << "[eBPF] Loading program from: " << ebpf_obj_path_ << std::endl;
        
        /* Load eBPF object file */
        struct bpf_object *obj = bpf_object__open(ebpf_obj_path_.c_str());
        if (!obj) {
            std::cerr << "[eBPF] Failed to open object file" << std::endl;
            return false;
        }
        
        /* Load into kernel */
        if (bpf_object__load(obj)) {
            std::cerr << "[eBPF] Failed to load object" << std::endl;
            bpf_object__close(obj);
            return false;
        }
        
        /* Find XDP program */
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_ids_filter");
        if (!prog) {
            std::cerr << "[eBPF] Failed to find xdp_ids_filter program" << std::endl;
            bpf_object__close(obj);
            return false;
        }
        
        /* Get file descriptor */
        int prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            std::cerr << "[eBPF] Failed to get program FD" << std::endl;
            bpf_object__close(obj);
            return false;
        }
        
        /* Get interface index */
        int ifindex = if_nametoindex(interface_.c_str());
        if (!ifindex) {
            std::cerr << "[eBPF] Failed to get interface index for: " << interface_ << std::endl;
            bpf_object__close(obj);
            return false;
        }
        
        /* Attach to XDP hook */
        if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL)) {
            std::cerr << "[eBPF] Failed to attach XDP program" << std::endl;
            bpf_object__close(obj);
            return false;
        }
        
        std::cout << "[eBPF] Successfully attached to " << interface_ << std::endl;
        
        /* Store object and FDs */
        bpf_obj_ = obj;
        prog_fd_ = prog_fd;
        ifindex_ = ifindex;
        
        /* Get map file descriptors */
        struct bpf_map *map;
        bpf_object__for_each_map(obj, map) {
            std::string name = bpf_map__name(map);
            int fd = bpf_map__fd(map);
            
            if (name == "packet_ring_buffer") {
                ringbuf_fd_ = fd;
                std::cout << "[eBPF] Found packet_ring_buffer: FD=" << fd << std::endl;
            } else if (name == "blocklist") {
                blocklist_fd_ = fd;
                std::cout << "[eBPF] Found blocklist: FD=" << fd << std::endl;
            } else if (name == "rate_limiter") {
                rate_limiter_fd_ = fd;
                std::cout << "[eBPF] Found rate_limiter: FD=" << fd << std::endl;
            } else if (name == "stats_map") {
                stats_fd_ = fd;
                std::cout << "[eBPF] Found stats_map: FD=" << fd << std::endl;
            }
        }
        
        return true;
    }
    
    /**
     * Start reading events from ring buffer
     * 
     * @param callback Function called for each packet event
     */
    void start_event_loop(std::function<void(const std::string&)> callback) {
        if (ringbuf_fd_ < 0) {
            std::cerr << "[eBPF] Ring buffer not initialized" << std::endl;
            return;
        }
        
        running_ = true;
        event_thread_ = std::thread([this, callback]() {
            this->event_loop(callback);
        });
    }
    
    /**
     * Stop reading events
     */
    void stop_event_loop() {
        running_ = false;
        if (event_thread_.joinable()) {
            event_thread_.join();
        }
    }
    
    /**
     * Add IP to blocklist
     * 
     * @param ip_str IP address as string (e.g., "192.168.1.100")
     */
    bool block_ip(const std::string& ip_str) {
        if (blocklist_fd_ < 0) {
            std::cerr << "[eBPF] Blocklist not initialized" << std::endl;
            return false;
        }
        
        /* Convert IP string to network byte order */
        uint32_t ip = inet_addr(ip_str.c_str());
        if (ip == INADDR_NONE) {
            std::cerr << "[eBPF] Invalid IP address: " << ip_str << std::endl;
            return false;
        }
        
        /* Add to blocklist */
        uint8_t action = 1;  /* Block */
        if (bpf_map_update_elem(blocklist_fd_, &ip, &action, BPF_ANY)) {
            std::cerr << "[eBPF] Failed to update blocklist" << std::endl;
            return false;
        }
        
        std::cout << "[eBPF] Blocked IP: " << ip_str << std::endl;
        return true;
    }
    
    /**
     * Remove IP from blocklist
     * 
     * @param ip_str IP address as string
     */
    bool unblock_ip(const std::string& ip_str) {
        if (blocklist_fd_ < 0) {
            std::cerr << "[eBPF] Blocklist not initialized" << std::endl;
            return false;
        }
        
        uint32_t ip = inet_addr(ip_str.c_str());
        if (ip == INADDR_NONE) {
            std::cerr << "[eBPF] Invalid IP address: " << ip_str << std::endl;
            return false;
        }
        
        if (bpf_map_delete_elem(blocklist_fd_, &ip)) {
            std::cerr << "[eBPF] Failed to remove from blocklist" << std::endl;
            return false;
        }
        
        std::cout << "[eBPF] Unblocked IP: " << ip_str << std::endl;
        return true;
    }
    
    /**
     * Get statistics
     */
    struct Stats {
        uint64_t packets_processed = 0;
        uint64_t packets_blocked = 0;
        uint64_t packets_allowed = 0;
        uint64_t rate_limited = 0;
        uint64_t parse_errors = 0;
    };
    
    Stats get_stats() {
        Stats stats;
        
        if (stats_fd_ < 0) {
            return stats;
        }
        
        uint32_t key = 0;
        struct {
            uint64_t packets_processed;
            uint64_t packets_blocked;
            uint64_t packets_allowed;
            uint64_t rate_limited;
            uint64_t parse_errors;
        } kernel_stats = {};
        
        if (bpf_map_lookup_elem(stats_fd_, &key, &kernel_stats) == 0) {
            stats.packets_processed = kernel_stats.packets_processed;
            stats.packets_blocked = kernel_stats.packets_blocked;
            stats.packets_allowed = kernel_stats.packets_allowed;
            stats.rate_limited = kernel_stats.rate_limited;
            stats.parse_errors = kernel_stats.parse_errors;
        }
        
        return stats;
    }
    
    /**
     * Print statistics
     */
    void print_stats() {
        Stats stats = get_stats();
        
        std::cout << "\n[eBPF Statistics]" << std::endl;
        std::cout << "  Packets Processed: " << stats.packets_processed << std::endl;
        std::cout << "  Packets Blocked:   " << stats.packets_blocked << std::endl;
        std::cout << "  Packets Allowed:   " << stats.packets_allowed << std::endl;
        std::cout << "  Rate Limited:      " << stats.rate_limited << std::endl;
        std::cout << "  Parse Errors:      " << stats.parse_errors << std::endl;
        
        if (stats.packets_processed > 0) {
            double block_rate = (100.0 * stats.packets_blocked) / stats.packets_processed;
            std::cout << "  Block Rate:        " << block_rate << "%" << std::endl;
        }
    }
    
    /**
     * Check if running
     */
    bool is_running() const {
        return running_.load();
    }
    
private:
    std::string interface_;
    std::string ebpf_obj_path_;
    
    struct bpf_object *bpf_obj_ = nullptr;
    int prog_fd_ = -1;
    int ifindex_ = -1;
    int ringbuf_fd_ = -1;
    int blocklist_fd_ = -1;
    int rate_limiter_fd_ = -1;
    int stats_fd_ = -1;
    
    std::atomic<bool> running_{false};
    std::thread event_thread_;
    std::atomic<uint64_t> packets_processed_{0};
    std::atomic<uint64_t> packets_blocked_{0};
    
    /**
     * Event loop — reads from ring buffer
     */
    void event_loop(std::function<void(const std::string&)> callback) {
        struct ring_buffer *rb = ring_buffer__new(ringbuf_fd_, nullptr, nullptr);
        if (!rb) {
            std::cerr << "[eBPF] Failed to create ring buffer" << std::endl;
            return;
        }
        
        std::cout << "[eBPF] Event loop started" << std::endl;
        
        while (running_.load()) {
            int ret = ring_buffer__poll(rb, 100);  /* 100ms timeout */
            
            if (ret < 0) {
                std::cerr << "[eBPF] Ring buffer poll error: " << ret << std::endl;
                break;
            }
            
            if (ret > 0) {
                packets_processed_ += ret;
            }
        }
        
        ring_buffer__free(rb);
        std::cout << "[eBPF] Event loop stopped" << std::endl;
    }
    
    /**
     * Cleanup
     */
    void cleanup() {
        stop_event_loop();
        
        if (prog_fd_ >= 0 && ifindex_ > 0) {
            std::cout << "[eBPF] Detaching from " << interface_ << std::endl;
            bpf_xdp_detach(ifindex_, XDP_FLAGS_DRV_MODE, NULL);
        }
        
        if (bpf_obj_) {
            bpf_object__close(bpf_obj_);
        }
    }
};

/**
 * Example usage
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface> [ebpf_obj_path]" << std::endl;
        std::cerr << "Example: " << argv[0] << " eth0 ./ebpf_kernel.o" << std::endl;
        return 1;
    }
    
    std::string interface = argv[1];
    std::string ebpf_path = (argc > 2) ? argv[2] : "./ebpf_kernel.o";
    
    EBPFLoader loader(interface, ebpf_path);
    
    if (!loader.load_and_attach()) {
        std::cerr << "Failed to load eBPF program" << std::endl;
        return 1;
    }
    
    /* Start event loop */
    loader.start_event_loop([](const std::string& event) {
        std::cout << "[Event] " << event << std::endl;
    });
    
    /* Example: Block an IP */
    std::cout << "\nBlocking 192.168.1.100..." << std::endl;
    loader.block_ip("192.168.1.100");
    
    /* Run for 10 seconds */
    std::cout << "Running for 10 seconds..." << std::endl;
    sleep(10);
    
    /* Print statistics */
    loader.print_stats();
    
    /* Cleanup */
    loader.stop_event_loop();
    
    return 0;
}


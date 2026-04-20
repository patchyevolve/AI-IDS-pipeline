/**
 * ids_auth.hpp
 * 
 * Authentication & Authorization for IDS
 * 
 * Features:
 *   - API key validation
 *   - Role-based access control (RBAC)
 *   - Decision signing & verification
 *   - Audit logging
 *   - Rate limiting
 * 
 * Mirrors: Python environment variable authentication
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <memory>
#include <cstring>

namespace ids {

// Authentication roles
enum class AuthRole {
    ADMIN,           // Full access
    OPERATOR,        // Can view and manage
    ANALYST,         // Can view only
    REMOTE_ATTACKER, // Limited - only send attacks
    GUEST            // Minimal access
};

// Permission flags
enum class Permission : uint32_t {
    READ_DECISIONS = 1 << 0,
    WRITE_DECISIONS = 1 << 1,
    READ_DATABASE = 1 << 2,
    WRITE_DATABASE = 1 << 3,
    MANAGE_USERS = 1 << 4,
    VIEW_LOGS = 1 << 5,
    SEND_ATTACKS = 1 << 6,
    EXPORT_DATA = 1 << 7,
    CONFIGURE_IDS = 1 << 8,
};

/**
 * AuthToken
 * 
 * Represents an authenticated session
 */
struct AuthToken {
    std::string token_id;
    std::string user_id;
    AuthRole role;
    uint32_t permissions;
    time_t issued_at;
    time_t expires_at;
    std::string source_ip;
    
    bool is_valid() const {
        return time(nullptr) < expires_at;
    }
    
    bool has_permission(Permission perm) const {
        return (permissions & static_cast<uint32_t>(perm)) != 0;
    }
};

/**
 * AuthenticatedDecision
 * 
 * Decision with authentication metadata
 */
struct AuthenticatedDecision {
    std::string decision;
    std::string attack_class;
    float confidence;
    
    // Authentication
    std::string issued_by;  // User ID
    time_t issued_at;
    std::string signature;  // HMAC-SHA256
    
    // Audit
    std::string source_ip;
    std::string user_agent;
};

/**
 * AuthenticationManager
 * 
 * Handles authentication, authorization, and audit logging
 */
class AuthenticationManager {
public:
    AuthenticationManager();
    ~AuthenticationManager();
    
    /**
     * Authenticate with API key
     * 
     * @param api_key API key from environment or config
     * @param source_ip Source IP address
     * @return AuthToken if valid, nullptr otherwise
     */
    std::shared_ptr<AuthToken> authenticate(
        const std::string& api_key,
        const std::string& source_ip
    );
    
    /**
     * Validate token
     * 
     * @param token Token to validate
     * @return true if valid and not expired
     */
    bool validate_token(const std::shared_ptr<AuthToken>& token);
    
    /**
     * Check if token has permission
     * 
     * @param token Token to check
     * @param permission Permission to verify
     * @return true if token has permission
     */
    bool check_permission(
        const std::shared_ptr<AuthToken>& token,
        Permission permission
    );
    
    /**
     * Sign a decision
     * 
     * @param decision Decision to sign
     * @param token Token of issuer
     * @return Signed decision
     */
    AuthenticatedDecision sign_decision(
        const std::string& decision,
        const std::string& attack_class,
        float confidence,
        const std::shared_ptr<AuthToken>& token
    );
    
    /**
     * Verify decision signature
     * 
     * @param decision Decision to verify
     * @return true if signature is valid
     */
    bool verify_decision(const AuthenticatedDecision& decision);
    
    /**
     * Log audit event
     * 
     * @param token Token of user
     * @param action Action performed
     * @param resource Resource affected
     * @param result Result (success/failure)
     */
    void audit_log(
        const std::shared_ptr<AuthToken>& token,
        const std::string& action,
        const std::string& resource,
        bool result
    );
    
    /**
     * Rate limit check
     * 
     * @param token Token to check
     * @param max_requests Max requests per minute
     * @return true if within limit
     */
    bool check_rate_limit(
        const std::shared_ptr<AuthToken>& token,
        int max_requests = 1000
    );
    
private:
    // API key to role mapping
    std::map<std::string, AuthRole> api_keys_;
    
    // Active tokens
    std::map<std::string, std::shared_ptr<AuthToken>> active_tokens_;
    
    // Rate limiting
    std::map<std::string, std::vector<time_t>> request_history_;
    
    // Signing key (from environment)
    std::string signing_key_;
    
    // Helper functions
    std::string generate_token_id();
    std::string compute_hmac_sha256(const std::string& message);
    AuthRole get_role_from_api_key(const std::string& api_key);
    uint32_t get_permissions_for_role(AuthRole role);
};

/**
 * RateLimiter
 * 
 * Token bucket rate limiter
 */
class RateLimiter {
public:
    RateLimiter(int capacity, int refill_rate)
        : capacity_(capacity), refill_rate_(refill_rate), tokens_(capacity), last_refill_(time(nullptr)) {}
    
    /**
     * Check if request is allowed
     * 
     * @return true if within rate limit
     */
    bool allow_request();
    
    /**
     * Get current token count
     */
    int get_tokens() const { return tokens_; }
    
private:
    int capacity_;
    int refill_rate_;  // tokens per second
    int tokens_;
    time_t last_refill_;
    
    void refill();
};

// Default role permissions
namespace auth {
    static const uint32_t ADMIN_PERMISSIONS = 
        static_cast<uint32_t>(Permission::READ_DECISIONS) |
        static_cast<uint32_t>(Permission::WRITE_DECISIONS) |
        static_cast<uint32_t>(Permission::READ_DATABASE) |
        static_cast<uint32_t>(Permission::WRITE_DATABASE) |
        static_cast<uint32_t>(Permission::MANAGE_USERS) |
        static_cast<uint32_t>(Permission::VIEW_LOGS) |
        static_cast<uint32_t>(Permission::EXPORT_DATA) |
        static_cast<uint32_t>(Permission::CONFIGURE_IDS);
    
    static const uint32_t OPERATOR_PERMISSIONS =
        static_cast<uint32_t>(Permission::READ_DECISIONS) |
        static_cast<uint32_t>(Permission::WRITE_DECISIONS) |
        static_cast<uint32_t>(Permission::READ_DATABASE) |
        static_cast<uint32_t>(Permission::VIEW_LOGS) |
        static_cast<uint32_t>(Permission::EXPORT_DATA);
    
    static const uint32_t ANALYST_PERMISSIONS =
        static_cast<uint32_t>(Permission::READ_DECISIONS) |
        static_cast<uint32_t>(Permission::READ_DATABASE) |
        static_cast<uint32_t>(Permission::VIEW_LOGS);
    
    static const uint32_t REMOTE_ATTACKER_PERMISSIONS =
        static_cast<uint32_t>(Permission::SEND_ATTACKS);
    
    static const uint32_t GUEST_PERMISSIONS =
        static_cast<uint32_t>(Permission::READ_DECISIONS);
}

}  // namespace ids

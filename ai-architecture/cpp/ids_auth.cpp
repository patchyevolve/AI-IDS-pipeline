/**
 * ids_auth.cpp
 * 
 * Authentication & Authorization Implementation
 */

#include "../include/ids_auth.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace ids {

// AuthenticationManager Implementation

AuthenticationManager::AuthenticationManager() {
    // Load signing key from environment
    const char* key_env = std::getenv("IDS_SIGNING_KEY");
    signing_key_ = key_env ? std::string(key_env) : "default-signing-key-change-in-production";
    
    // Initialize API keys (in production, load from secure config)
    api_keys_["admin-key-12345"] = AuthRole::ADMIN;
    api_keys_["operator-key-67890"] = AuthRole::OPERATOR;
    api_keys_["analyst-key-abcde"] = AuthRole::ANALYST;
    api_keys_["attacker-key-fghij"] = AuthRole::REMOTE_ATTACKER;
    api_keys_["guest-key-klmno"] = AuthRole::GUEST;
}

std::shared_ptr<AuthToken> AuthenticationManager::authenticate(
    const std::string& api_key,
    const std::string& source_ip
) {
    // Check if API key exists
    auto it = api_keys_.find(api_key);
    if (it == api_keys_.end()) {
        std::cerr << "[auth] Invalid API key from " << source_ip << std::endl;
        return nullptr;
    }
    
    // Create token
    auto token = std::make_shared<AuthToken>();
    token->token_id = generate_token_id();
    token->user_id = "user_" + token->token_id;
    token->role = it->second;
    token->permissions = get_permissions_for_role(it->second);
    token->issued_at = time(nullptr);
    token->expires_at = token->issued_at + 3600;  // 1 hour expiry
    token->source_ip = source_ip;
    
    // Store token
    active_tokens_[token->token_id] = token;
    
    std::cout << "[auth] Token issued for " << source_ip << " (role: " 
              << static_cast<int>(token->role) << ")" << std::endl;
    
    return token;
}

bool AuthenticationManager::validate_token(const std::shared_ptr<AuthToken>& token) {
    if (!token) return false;
    
    // Check if token exists in active tokens
    auto it = active_tokens_.find(token->token_id);
    if (it == active_tokens_.end()) {
        return false;
    }
    
    // Check if expired
    return token->is_valid();
}

bool AuthenticationManager::check_permission(
    const std::shared_ptr<AuthToken>& token,
    Permission permission
) {
    if (!validate_token(token)) {
        return false;
    }
    
    return token->has_permission(permission);
}

AuthenticatedDecision AuthenticationManager::sign_decision(
    const std::string& decision,
    const std::string& attack_class,
    float confidence,
    const std::shared_ptr<AuthToken>& token
) {
    AuthenticatedDecision auth_decision;
    auth_decision.decision = decision;
    auth_decision.attack_class = attack_class;
    auth_decision.confidence = confidence;
    auth_decision.issued_by = token->user_id;
    auth_decision.issued_at = time(nullptr);
    auth_decision.source_ip = token->source_ip;
    
    // Create message to sign
    std::stringstream ss;
    ss << decision << "|" << attack_class << "|" << std::fixed << std::setprecision(4) 
       << confidence << "|" << auth_decision.issued_at;
    
    // Sign with HMAC-SHA256
    auth_decision.signature = compute_hmac_sha256(ss.str());
    
    return auth_decision;
}

bool AuthenticationManager::verify_decision(const AuthenticatedDecision& decision) {
    // Recreate message
    std::stringstream ss;
    ss << decision.decision << "|" << decision.attack_class << "|" 
       << std::fixed << std::setprecision(4) << decision.confidence << "|" 
       << decision.issued_at;
    
    // Compute expected signature
    std::string expected_sig = compute_hmac_sha256(ss.str());
    
    // Compare signatures
    return decision.signature == expected_sig;
}

void AuthenticationManager::audit_log(
    const std::shared_ptr<AuthToken>& token,
    const std::string& action,
    const std::string& resource,
    bool result
) {
    std::cout << "[audit] user=" << token->user_id 
              << " action=" << action 
              << " resource=" << resource 
              << " result=" << (result ? "success" : "failure")
              << " ip=" << token->source_ip << std::endl;
}

bool AuthenticationManager::check_rate_limit(
    const std::shared_ptr<AuthToken>& token,
    int max_requests
) {
    auto& history = request_history_[token->token_id];
    time_t now = time(nullptr);
    
    // Remove old entries (older than 1 minute)
    history.erase(
        std::remove_if(history.begin(), history.end(),
                      [now](time_t t) { return (now - t) > 60; }),
        history.end()
    );
    
    // Check if within limit
    if (history.size() >= static_cast<size_t>(max_requests)) {
        return false;
    }
    
    // Add current request
    history.push_back(now);
    return true;
}

std::string AuthenticationManager::generate_token_id() {
    static int counter = 0;
    std::stringstream ss;
    ss << std::hex << time(nullptr) << "_" << counter++;
    return ss.str();
}

std::string AuthenticationManager::compute_hmac_sha256(const std::string& message) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    HMAC(EVP_sha256(),
         reinterpret_cast<const unsigned char*>(signing_key_.c_str()),
         signing_key_.length(),
         reinterpret_cast<const unsigned char*>(message.c_str()),
         message.length(),
         hash,
         &hash_len);
    
    // Convert to hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

AuthRole AuthenticationManager::get_role_from_api_key(const std::string& api_key) {
    auto it = api_keys_.find(api_key);
    if (it != api_keys_.end()) {
        return it->second;
    }
    return AuthRole::GUEST;
}

uint32_t AuthenticationManager::get_permissions_for_role(AuthRole role) {
    switch (role) {
        case AuthRole::ADMIN:
            return auth::ADMIN_PERMISSIONS;
        case AuthRole::OPERATOR:
            return auth::OPERATOR_PERMISSIONS;
        case AuthRole::ANALYST:
            return auth::ANALYST_PERMISSIONS;
        case AuthRole::REMOTE_ATTACKER:
            return auth::REMOTE_ATTACKER_PERMISSIONS;
        case AuthRole::GUEST:
        default:
            return auth::GUEST_PERMISSIONS;
    }
}

// RateLimiter Implementation

bool RateLimiter::allow_request() {
    refill();
    
    if (tokens_ > 0) {
        tokens_--;
        return true;
    }
    
    return false;
}

void RateLimiter::refill() {
    time_t now = time(nullptr);
    int elapsed = now - last_refill_;
    
    if (elapsed > 0) {
        tokens_ = std::min(capacity_, tokens_ + (elapsed * refill_rate_));
        last_refill_ = now;
    }
}

}  // namespace ids

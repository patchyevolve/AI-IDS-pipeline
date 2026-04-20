/**
 * ids_decision_enhanced.hpp
 * 
 * Enhanced Decision Engine with all upgrades:
 *   - Mutation prediction
 *   - Authentication & authorization
 *   - Improved fitness function
 *   - Database context filtering
 *   - CNN gate heuristic
 *   - Decoder score suppression fixes
 * 
 * Mirrors: Python upgrades in decoder_engine.py + mutation_predictor.py
 */

#pragma once

#include "ids_decision.hpp"
#include "ids_mutation_predictor.hpp"
#include "ids_auth.hpp"
#include <memory>

namespace ids {

/**
 * EnhancedDecisionEngine
 * 
 * Wraps base DecisionEngine with mutation prediction and authentication
 */
class EnhancedDecisionEngine {
public:
    EnhancedDecisionEngine(
        std::shared_ptr<MutationPredictor> predictor,
        std::shared_ptr<AuthenticationManager> auth_manager
    )
        : predictor_(predictor),
          auth_manager_(auth_manager),
          mutation_detection_enabled_(true),
          auth_enabled_(true) {}
    
    /**
     * Make decision with mutation awareness and authentication
     * 
     * @param base_decision Base decision from reasoning engine
     * @param event Network event
     * @param gs Global state
     * @param token Authentication token
     * @return Enhanced decision with mutation info
     */
    struct EnhancedDecision {
        Decision base_decision;
        Decision final_decision;
        float confidence;
        std::string explanation;
        
        // Mutation prediction
        MutationScores mutation_scores;
        bool mutation_detected = false;
        
        // Authentication
        AuthenticatedDecision authenticated_decision;
        bool auth_verified = false;
        
        // Audit
        std::string issued_by;
        time_t issued_at;
    };
    
    EnhancedDecision make_decision(
        const Decision& base_decision,
        const Event& event,
        const GlobalState& gs,
        const std::shared_ptr<AuthToken>& token
    );
    
    /**
     * Enable/disable mutation prediction
     */
    void set_mutation_detection(bool enabled) {
        mutation_detection_enabled_ = enabled;
    }
    
    /**
     * Enable/disable authentication
     */
    void set_auth_enabled(bool enabled) {
        auth_enabled_ = enabled;
    }
    
private:
    std::shared_ptr<MutationPredictor> predictor_;
    std::shared_ptr<AuthenticationManager> auth_manager_;
    bool mutation_detection_enabled_;
    bool auth_enabled_;
    
    // Helper to upgrade decision based on mutation score
    Decision upgrade_decision_for_mutation(
        const Decision& base_decision,
        float mutation_score
    );
};

/**
 * FitnessCalculator
 * 
 * Corrected fitness function for attacker evolution
 * 
 * Mirrors: Python mutator.py fitness property
 */
class FitnessCalculator {
public:
    /**
     * Calculate fitness score for attack profile
     * 
     * @param sent Total attacks sent
     * @param blocked Attacks blocked
     * @param alerted Attacks that triggered alert
     * @param evaded Attacks that evaded (Log/Ignore)
     * @return Fitness score [0, 1]
     */
    static float calculate_fitness(
        int sent,
        int blocked,
        int alerted,
        int evaded
    ) {
        if (sent < 3) return 0.5f;  // Unknown - neutral
        if (sent == 0) return 0.5f;
        
        // Fitness = (successes - failures) / sent
        // Where:
        //   failures = blocked (detected and blocked)
        //   successes = sent - failures - alerted (true evasions, not Alert)
        //   neutral = Log/Ignore (not rewarded, not penalized)
        
        int failures = blocked;
        int successes = sent - failures - alerted;
        
        float raw_fitness = static_cast<float>(successes - failures) / sent;
        return std::max(0.0f, std::min(1.0f, raw_fitness));
    }
    
    /**
     * Calculate evasion rate
     * 
     * @param sent Total attacks sent
     * @param blocked Attacks blocked
     * @param alerted Attacks alerted
     * @return Evasion rate [0, 1]
     */
    static float calculate_evasion_rate(
        int sent,
        int blocked,
        int alerted
    ) {
        if (sent == 0) return 0.5f;
        
        // True evasion = not blocked and not alerted
        int true_evasions = sent - blocked - alerted;
        return static_cast<float>(true_evasions) / sent;
    }
};

/**
 * DatabaseContextFilter
 * 
 * Filters database records for high quality matches
 * 
 * Mirrors: Python decoder_engine.py database context filtering
 */
class DatabaseContextFilter {
public:
    /**
     * Filter records to high-quality matches only
     * 
     * @param records Database records to filter
     * @param min_similarity Minimum similarity threshold (default 0.85)
     * @param min_confidence Minimum confidence threshold (default 0.60)
     * @return Filtered high-quality records
     */
    static std::vector<std::map<std::string, float>> filter_high_quality(
        const std::vector<std::map<std::string, float>>& records,
        float min_similarity = 0.85f,
        float min_confidence = 0.60f
    ) {
        std::vector<std::map<std::string, float>> filtered;
        
        for (const auto& rec : records) {
            float similarity = rec.at("similarity");
            float confidence = rec.at("confidence");
            
            if (similarity > min_similarity && confidence > min_confidence) {
                filtered.push_back(rec);
            }
        }
        
        return filtered;
    }
    
    /**
     * Get database boost for decision
     * 
     * @param high_quality_records Filtered high-quality records
     * @return Boost value [0, 0.20]
     */
    static float get_db_boost(
        const std::vector<std::map<std::string, float>>& high_quality_records
    ) {
        if (high_quality_records.empty()) return 0.0f;
        return 0.20f;  // Stronger boost for high-quality matches
    }
    
    /**
     * Check if should override decision
     * 
     * @param best_match Best matching record
     * @return Decision override string, or empty if no override
     */
    static std::string get_decision_override(
        const std::map<std::string, float>& best_match
    ) {
        float similarity = best_match.at("similarity");
        float confidence = best_match.at("confidence");
        
        // If similarity is very high AND confidence is high, use the known decision
        if (similarity > 0.92f && confidence > 0.75f) {
            return best_match.at("decision");
        }
        
        return "";  // No override
    }
};

/**
 * CNNGateHeuristic
 * 
 * Feature-based gate heuristic for attack detection
 * 
 * Mirrors: Python cnn_engine.py GateCNN.forward()
 */
class CNNGateHeuristic {
public:
    /**
     * Calculate gate probability using feature heuristic
     * 
     * @param entropy Normalized entropy [0, 1]
     * @param rate_hz Normalized rate [0, 1]
     * @param bytes_in Normalized bytes_in [0, 1]
     * @param bytes_out Normalized bytes_out [0, 1]
     * @return Gate probability [0, 1]
     */
    static float calculate_gate_probability(
        float entropy,
        float rate_hz,
        float bytes_in,
        float bytes_out
    ) {
        float prob = 0.0f;
        
        // Signal 1: High entropy (encrypted/obfuscated traffic)
        if (entropy > 0.60f) {
            prob += 0.35f;
        }
        
        // Signal 2: High rate (DoS/scanning/brute force)
        if (rate_hz > 0.20f) {
            prob += 0.35f;
        }
        
        // Signal 3: Large payload (exfiltration/C2)
        if (bytes_in > 0.40f || bytes_out > 0.40f) {
            prob += 0.25f;
        }
        
        // Signal 4: Combination of moderate entropy + rate
        if (entropy > 0.30f && rate_hz > 0.05f) {
            prob += 0.15f;
        }
        
        // Signal 5: Asymmetric traffic (exfiltration)
        if (bytes_out > 0.30f && bytes_in < 0.20f) {
            prob += 0.20f;
        }
        
        return std::min(prob, 1.0f);
    }
};

/**
 * DecoderScoreFusion
 * 
 * Improved score fusion with proper suppression logic
 * 
 * Mirrors: Python decoder_engine.py fuse_score()
 */
class DecoderScoreFusion {
public:
    struct FusionWeights {
        float w_local = 0.3f;
        float w_segment = 0.2f;
        float w_history = 0.2f;
        float w_drift = 0.1f;
        float w_retrieval = 0.1f;
        float w_rule = 0.1f;
    };
    
    /**
     * Fuse multiple signals into final score
     * 
     * @param local_score CNN local score
     * @param segment_trend RNN segment trend
     * @param anomaly_hist RNN anomaly history
     * @param drift_score RNN drift score
     * @param retrieval_boost Database retrieval boost
     * @param rule_boost Rule-based boost
     * @param meta_fused Meta-learning coordinator score
     * @param db_boost Database context boost
     * @param gate_prob Gate CNN probability
     * @param weights Fusion weights
     * @return Fused score [0, 1]
     */
    static float fuse_scores(
        float local_score,
        float segment_trend,
        float anomaly_hist,
        float drift_score,
        float retrieval_boost,
        float rule_boost,
        float meta_fused,
        float db_boost,
        float gate_prob,
        const FusionWeights& weights
    ) {
        float drift_norm = std::min(drift_score / 10.0f, 1.0f);
        
        float fused = (weights.w_local * local_score +
                      weights.w_segment * segment_trend +
                      weights.w_history * anomaly_hist +
                      weights.w_drift * drift_norm +
                      retrieval_boost + rule_boost + meta_fused + db_boost) / 2.0f;
        
        // If Gate CNN says it's an attack, boost the score
        if (gate_prob > 0.5f) {
            fused = std::max(fused, local_score + retrieval_boost);
        } else {
            // During training, don't suppress scores too aggressively
            // Only suppress if Gate CNN is VERY confident it's normal (prob < 0.15)
            if (gate_prob < 0.15f) {
                fused = std::min(fused, 0.35f);  // Suppress only if very confident normal
            }
            // Otherwise, let other signals (RNN, DB) contribute
        }
        
        return std::max(0.0f, std::min(1.0f, fused));
    }
};

}  // namespace ids

/**
 * ids_mutation_predictor.hpp
 * 
 * Mutation Predictor — Anticipates attack mutations before they arrive.
 * 
 * Mirrors: ai-architecture/decoder/mutation_predictor.py
 * 
 * Strategy:
 *   1. Analyze existing threats in database
 *   2. Learn mutation patterns (what changes when attacks evade)
 *   3. Generate predicted mutations of current attack
 *   4. Score incoming traffic against predicted mutations
 *   5. Block predicted mutations with high confidence
 * 
 * This allows IDS to think ahead: "If this is a DoS, what mutations might come next?"
 */

#pragma once

#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <algorithm>
#include <memory>

namespace ids {

// Mutation types
enum class MutationType {
    RATE_REDUCTION,
    ENTROPY_INCREASE,
    PORT_ROTATION,
    FRAGMENTATION,
    TIMING_JITTER,
    PROTOCOL_SWITCHING,
    PAYLOAD_VARIATION,
    UNKNOWN
};

// Predicted mutation structure
struct PredictedMutation {
    int id;
    MutationType type;
    std::string description;
    float confidence;
    
    // Feature predictions
    float predicted_rate = 0.0f;
    float predicted_entropy = 0.0f;
    int predicted_port = 0;
    float predicted_bytes = 0.0f;
    float factor = 1.0f;
    float delta = 0.0f;
    
    PredictedMutation() : id(0), type(MutationType::UNKNOWN), confidence(0.0f) {}
};

// Mutation match result
struct MutationMatch {
    int mutation_id;
    MutationType mutation_type;
    float match_score;
    std::string description;
};

// Mutation scores result
struct MutationScores {
    std::vector<MutationMatch> mutation_matches;
    float max_mutation_score = 0.0f;
    bool predicted_mutation_detected = false;
};

/**
 * MutationPredictor
 * 
 * Learns mutation patterns from database and predicts likely variants.
 */
class MutationPredictor {
public:
    MutationPredictor() = default;
    ~MutationPredictor() = default;
    
    /**
     * Learn mutation patterns from database records
     */
    void learn_from_database(const std::vector<std::map<std::string, float>>& db_records);
    
    /**
     * Predict likely mutations for given attack class
     * 
     * @param current_event Current network event features
     * @param attack_class Attack classification (e.g., "DoS/DDoS")
     * @param k Number of mutations to predict
     * @return Vector of predicted mutations
     */
    std::vector<PredictedMutation> predict_mutations(
        const std::map<std::string, float>& current_event,
        const std::string& attack_class,
        int k = 5
    );
    
    /**
     * Score incoming event against predicted mutations
     * 
     * @param current_event Incoming network event
     * @param predicted_mutations Predicted mutations to check against
     * @return Mutation scores with matches
     */
    MutationScores score_against_mutations(
        const std::map<std::string, float>& current_event,
        const std::vector<PredictedMutation>& predicted_mutations
    );
    
private:
    // Mutation patterns for each attack class
    std::map<std::string, std::map<std::string, std::vector<float>>> mutation_patterns;
    
    // Learned threat patterns
    std::map<std::string, std::vector<std::map<std::string, float>>> threat_patterns;
    
    // Initialize mutation patterns
    void init_mutation_patterns();
    
    // Helper functions
    float calculate_rate_match(float current, float predicted);
    float calculate_entropy_match(float current, float predicted);
    float calculate_bytes_match(float current, float predicted);
};

/**
 * MutationAwareDecoder
 * 
 * Wraps base decoder to add mutation prediction capability.
 * Upgrades decisions based on predicted mutation detection.
 */
class MutationAwareDecoder {
public:
    MutationAwareDecoder(MutationPredictor* predictor)
        : predictor_(predictor), last_db_sync_(0), sync_interval_(300) {}
    
    ~MutationAwareDecoder() = default;
    
    /**
     * Decode with mutation awareness
     * 
     * @param base_decision Base decision from decoder
     * @param attack_class Attack classification
     * @param current_event Current network event
     * @return Upgraded decision based on mutation detection
     */
    struct DecoderOutput {
        std::string decision;
        std::string attack_class;
        float confidence;
        std::string explanation;
        MutationScores mutation_prediction;
    };
    
    DecoderOutput decode_with_mutation_awareness(
        const DecoderOutput& base_decision,
        const std::string& attack_class,
        const std::map<std::string, float>& current_event
    );
    
    /**
     * Sync database patterns for learning
     */
    void sync_database_patterns(const std::vector<std::map<std::string, float>>& db_records);
    
private:
    MutationPredictor* predictor_;
    time_t last_db_sync_;
    int sync_interval_;  // seconds
    
    // Decision upgrade logic
    std::string upgrade_decision(
        const std::string& base_decision,
        float mutation_score
    );
};

// Mutation pattern constants
namespace mutation_patterns {
    // DoS/DDoS mutations
    static const std::vector<float> DOS_RATE_REDUCTION = {0.5f, 0.3f, 0.1f};
    static const std::vector<float> DOS_ENTROPY_INCREASE = {0.1f, 0.2f, 0.3f};
    static const std::vector<int> DOS_PORT_ROTATION = {80, 443, 8080, 8443};
    static const std::vector<float> DOS_FRAGMENTATION = {0.5f, 0.3f};
    
    // PortScan mutations
    static const std::vector<float> PORTSCAN_RATE_REDUCTION = {0.5f, 0.2f, 0.1f};
    static const std::vector<float> PORTSCAN_ENTROPY_INCREASE = {0.1f, 0.15f};
    
    // BruteForce mutations
    static const std::vector<float> BRUTEFORCE_RATE_REDUCTION = {0.5f, 0.3f, 0.1f};
    static const std::vector<float> BRUTEFORCE_TIMING_VARIATION = {0.1f, 0.5f, 1.0f};
    static const std::vector<int> BRUTEFORCE_PORT_SWITCHING = {22, 3389, 445};
    
    // C2/Exfiltration mutations
    static const std::vector<float> C2_RATE_INCREASE = {1.5f, 2.0f};
    static const std::vector<float> C2_ENTROPY_VARIATION = {0.05f, 0.1f};
    
    // DNSTunnel mutations
    static const std::vector<float> DNS_QUERY_SIZE_VARIATION = {0.5f, 1.5f, 2.0f};
    static const std::vector<float> DNS_FREQUENCY_VARIATION = {0.5f, 0.3f, 0.1f};
}

}  // namespace ids

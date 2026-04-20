/**
 * ids_mutation_predictor.cpp
 * 
 * Mutation Predictor Implementation
 * Mirrors: ai-architecture/decoder/mutation_predictor.py
 */

#include "../include/ids_mutation_predictor.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

namespace ids {

void MutationPredictor::init_mutation_patterns() {
    // DoS/DDoS patterns
    mutation_patterns["DoS/DDoS"] = {
        {"rate_reduction", {0.5f, 0.3f, 0.1f}},
        {"entropy_increase", {0.1f, 0.2f, 0.3f}},
        {"fragmentation", {0.5f, 0.3f}},
        {"timing_jitter", {0.1f, 0.5f, 1.0f}}
    };
    
    // PortScan patterns
    mutation_patterns["PortScan"] = {
        {"rate_reduction", {0.5f, 0.2f, 0.1f}},
        {"entropy_increase", {0.1f, 0.15f}},
        {"port_rotation", {80.0f, 443.0f, 8080.0f, 8443.0f}}
    };
    
    // BruteForce patterns
    mutation_patterns["BruteForce"] = {
        {"rate_reduction", {0.5f, 0.3f, 0.1f}},
        {"timing_variation", {0.1f, 0.5f, 1.0f}},
        {"port_switching", {22.0f, 3389.0f, 445.0f}}
    };
    
    // C2/Exfiltration patterns
    mutation_patterns["C2/Exfiltration"] = {
        {"rate_increase", {1.5f, 2.0f}},
        {"entropy_variation", {0.05f, 0.1f}},
        {"protocol_switching", {6.0f, 17.0f}}  // TCP, UDP
    };
    
    // DNSTunnel patterns
    mutation_patterns["DNSTunnel"] = {
        {"query_size_variation", {0.5f, 1.5f, 2.0f}},
        {"frequency_variation", {0.5f, 0.3f, 0.1f}}
    };
}

void MutationPredictor::learn_from_database(
    const std::vector<std::map<std::string, float>>& db_records) {
    
    if (db_records.empty()) return;
    
    // Group records by attack class
    std::map<std::string, std::vector<std::map<std::string, float>>> grouped;
    
    for (const auto& record : db_records) {
        auto it = record.find("attack_class");
        if (it != record.end()) {
            std::string attack_class = std::to_string(static_cast<int>(it->second));
            grouped[attack_class].push_back(record);
        }
    }
    
    // Learn patterns for each attack class
    for (auto& [attack_class, records] : grouped) {
        threat_patterns[attack_class] = records;
    }
}

std::vector<PredictedMutation> MutationPredictor::predict_mutations(
    const std::map<std::string, float>& current_event,
    const std::string& attack_class,
    int k) {
    
    std::vector<PredictedMutation> predictions;
    
    // Get mutation patterns for this attack class
    auto it = mutation_patterns.find(attack_class);
    if (it == mutation_patterns.end()) {
        return predictions;  // No known mutations for this class
    }
    
    int mutation_id = 0;
    
    // Rate reduction mutations
    if (it->second.count("rate_reduction")) {
        auto& factors = it->second.at("rate_reduction");
        for (size_t i = 0; i < factors.size() && predictions.size() < static_cast<size_t>(k); ++i) {
            PredictedMutation pm;
            pm.id = mutation_id++;
            pm.type = MutationType::RATE_REDUCTION;
            pm.description = "Rate reduction by " + std::to_string(static_cast<int>(factors[i] * 100)) + "%";
            pm.confidence = 0.8f - (i * 0.1f);  // Decreasing confidence
            pm.factor = factors[i];
            
            auto rate_it = current_event.find("rate_hz");
            if (rate_it != current_event.end()) {
                pm.predicted_rate = rate_it->second * factors[i];
            }
            
            predictions.push_back(pm);
        }
    }
    
    // Entropy increase mutations
    if (it->second.count("entropy_increase")) {
        auto& deltas = it->second.at("entropy_increase");
        for (size_t i = 0; i < deltas.size() && predictions.size() < static_cast<size_t>(k); ++i) {
            PredictedMutation pm;
            pm.id = mutation_id++;
            pm.type = MutationType::ENTROPY_INCREASE;
            pm.description = "Entropy increase by " + std::to_string(static_cast<int>(deltas[i] * 100)) + "%";
            pm.confidence = 0.75f - (i * 0.1f);
            pm.delta = deltas[i];
            
            auto entropy_it = current_event.find("entropy");
            if (entropy_it != current_event.end()) {
                pm.predicted_entropy = entropy_it->second + deltas[i];
            }
            
            predictions.push_back(pm);
        }
    }
    
    // Port rotation mutations
    if (it->second.count("port_rotation")) {
        auto& ports = it->second.at("port_rotation");
        for (size_t i = 0; i < ports.size() && predictions.size() < static_cast<size_t>(k); ++i) {
            PredictedMutation pm;
            pm.id = mutation_id++;
            pm.type = MutationType::PORT_ROTATION;
            pm.description = "Port rotation to " + std::to_string(static_cast<int>(ports[i]));
            pm.confidence = 0.7f - (i * 0.1f);
            pm.predicted_port = static_cast<int>(ports[i]);
            
            predictions.push_back(pm);
        }
    }
    
    // Fragmentation mutations
    if (it->second.count("fragmentation")) {
        auto& factors = it->second.at("fragmentation");
        for (size_t i = 0; i < factors.size() && predictions.size() < static_cast<size_t>(k); ++i) {
            PredictedMutation pm;
            pm.id = mutation_id++;
            pm.type = MutationType::FRAGMENTATION;
            pm.description = "Fragmentation factor " + std::to_string(static_cast<int>(factors[i] * 100)) + "%";
            pm.confidence = 0.65f - (i * 0.1f);
            pm.factor = factors[i];
            
            auto bytes_it = current_event.find("bytes_out");
            if (bytes_it != current_event.end()) {
                pm.predicted_bytes = bytes_it->second * factors[i];
            }
            
            predictions.push_back(pm);
        }
    }
    
    // Timing jitter mutations
    if (it->second.count("timing_jitter")) {
        auto& jitters = it->second.at("timing_jitter");
        for (size_t i = 0; i < jitters.size() && predictions.size() < static_cast<size_t>(k); ++i) {
            PredictedMutation pm;
            pm.id = mutation_id++;
            pm.type = MutationType::TIMING_JITTER;
            pm.description = "Timing jitter factor " + std::to_string(static_cast<int>(jitters[i] * 100)) + "%";
            pm.confidence = 0.6f - (i * 0.1f);
            pm.factor = jitters[i];
            
            predictions.push_back(pm);
        }
    }
    
    return predictions;
}

MutationScores MutationPredictor::score_against_mutations(
    const std::map<std::string, float>& current_event,
    const std::vector<PredictedMutation>& predicted_mutations) {
    
    MutationScores scores;
    scores.max_mutation_score = 0.0f;
    scores.predicted_mutation_detected = false;
    
    for (const auto& mutation : predicted_mutations) {
        float match_score = 0.0f;
        
        switch (mutation.type) {
        case MutationType::RATE_REDUCTION: {
            auto it = current_event.find("rate_hz");
            if (it != current_event.end()) {
                match_score = calculate_rate_match(it->second, mutation.predicted_rate);
            }
            break;
        }
        
        case MutationType::ENTROPY_INCREASE: {
            auto it = current_event.find("entropy");
            if (it != current_event.end()) {
                match_score = calculate_entropy_match(it->second, mutation.predicted_entropy);
            }
            break;
        }
        
        case MutationType::PORT_ROTATION: {
            auto it = current_event.find("port_dst");
            if (it != current_event.end()) {
                int current_port = static_cast<int>(it->second);
                if (current_port == mutation.predicted_port) {
                    match_score = 0.9f;
                }
            }
            break;
        }
        
        case MutationType::FRAGMENTATION: {
            auto it = current_event.find("bytes_out");
            if (it != current_event.end()) {
                match_score = calculate_bytes_match(it->second, mutation.predicted_bytes);
            }
            break;
        }
        
        case MutationType::TIMING_JITTER:
            // Timing jitter is harder to detect in single event
            match_score = 0.3f;
            break;
        
        default:
            match_score = 0.0f;
        }
        
        // Weight by mutation confidence
        match_score *= mutation.confidence;
        
        if (match_score > 0.5f) {
            MutationMatch mm;
            mm.mutation_id = mutation.id;
            mm.mutation_type = mutation.type;
            mm.match_score = match_score;
            mm.description = mutation.description;
            
            scores.mutation_matches.push_back(mm);
            scores.max_mutation_score = std::max(scores.max_mutation_score, match_score);
            
            if (match_score > 0.7f) {
                scores.predicted_mutation_detected = true;
            }
        }
    }
    
    return scores;
}

float MutationPredictor::calculate_rate_match(float current, float predicted) {
    if (predicted == 0.0f) return 0.0f;
    float ratio = current / predicted;
    // Match if within 20% of predicted
    if (ratio >= 0.8f && ratio <= 1.2f) {
        return 0.9f - std::abs(ratio - 1.0f) * 0.5f;
    }
    return 0.0f;
}

float MutationPredictor::calculate_entropy_match(float current, float predicted) {
    if (predicted == 0.0f) return 0.0f;
    float diff = std::abs(current - predicted);
    // Match if within 0.1 of predicted
    if (diff <= 0.1f) {
        return 0.9f - diff;
    }
    return 0.0f;
}

float MutationPredictor::calculate_bytes_match(float current, float predicted) {
    if (predicted == 0.0f) return 0.0f;
    float ratio = current / predicted;
    // Match if within 30% of predicted
    if (ratio >= 0.7f && ratio <= 1.3f) {
        return 0.85f - std::abs(ratio - 1.0f) * 0.4f;
    }
    return 0.0f;
}

// MutationAwareDecoder Implementation

MutationAwareDecoder::DecoderOutput MutationAwareDecoder::decode_with_mutation_awareness(
    const DecoderOutput& base_decision,
    const std::string& attack_class,
    const std::map<std::string, float>& current_event) {
    
    DecoderOutput output = base_decision;
    
    if (!predictor_) return output;
    
    // Predict mutations for this attack class
    auto predicted_mutations = predictor_->predict_mutations(current_event, attack_class, 5);
    
    if (predicted_mutations.empty()) {
        return output;
    }
    
    // Score current event against predictions
    output.mutation_prediction = predictor_->score_against_mutations(
        current_event, predicted_mutations);
    
    // Upgrade decision if predicted mutation detected
    if (output.mutation_prediction.predicted_mutation_detected) {
        output.decision = upgrade_decision(base_decision.decision,
                                          output.mutation_prediction.max_mutation_score);
        output.confidence = std::max(base_decision.confidence,
                                    output.mutation_prediction.max_mutation_score);
        output.explanation += " [predicted mutation detected]";
    }
    
    return output;
}

void MutationAwareDecoder::sync_database_patterns(
    const std::vector<std::map<std::string, float>>& db_records) {
    
    time_t now = time(nullptr);
    if ((now - last_db_sync_) < sync_interval_) {
        return;  // Too soon to sync
    }
    
    if (predictor_) {
        predictor_->learn_from_database(db_records);
        last_db_sync_ = now;
    }
}

std::string MutationAwareDecoder::upgrade_decision(
    const std::string& base_decision,
    float mutation_score) {
    
    if (mutation_score > 0.8f) {
        if (base_decision == "alert") return "block";
        if (base_decision == "log") return "alert";
        return "escalate";
    } else if (mutation_score > 0.6f) {
        if (base_decision == "log") return "alert";
        if (base_decision == "ignore") return "log";
        return base_decision;
    }
    
    return base_decision;
}

}  // namespace ids

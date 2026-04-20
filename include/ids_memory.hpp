#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <numeric>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace ids {

// VectorStore — thread-safe vector graph index
class VectorGraphStore {
public:
    void set_max_size(size_t n) { max_size_ = n; }
    VectorGraphStore() = default;
    
    // Disable copy to enforce thread safety, enable move
    VectorGraphStore(const VectorGraphStore&) = delete;
    VectorGraphStore& operator=(const VectorGraphStore&) = delete;
    
    VectorGraphStore(VectorGraphStore&& other) noexcept {
        std::lock_guard<std::mutex> lk(other.mu_);
        max_size_ = other.max_size_;
        edge_threshold_ = other.edge_threshold_;
        next_id_ = other.next_id_;
        records_ = std::move(other.records_);
        adjacency_list_ = std::move(other.adjacency_list_);
    }
    
    VectorGraphStore& operator=(VectorGraphStore&& other) noexcept {
        if (this != &other) {
            std::scoped_lock lk(mu_, other.mu_);
            max_size_ = other.max_size_;
            edge_threshold_ = other.edge_threshold_;
            next_id_ = other.next_id_;
            records_ = std::move(other.records_);
            adjacency_list_ = std::move(other.adjacency_list_);
        }
        return *this;
    }
    void set_edge_threshold(float t) { edge_threshold_ = t; }

    void insert(MemoryRecord rec) {
        std::lock_guard<std::mutex> lk(mu_);
        rec.id = next_id_++;
        
        // Graph edge building
        if (!records_.empty()) {
            float qnorm = l2norm(rec.embedding);
            for (size_t i = 0; i < records_.size(); ++i) {
                float sim = cosine(rec.embedding, records_[i].embedding, qnorm);
                if (sim >= edge_threshold_) {
                    adjacency_list_[records_.size()].push_back(i);
                    adjacency_list_[i].push_back(records_.size());
                }
            }
        }
        
        records_.push_back(std::move(rec));
        if (records_.size() > max_size_) evict();
    }

    std::vector<MemoryRecord> search(const Vec& query, size_t k,
                                     float max_age_s = 1e9f,
                                     float recency_tau = 600.f,
                                     float w_sim = 0.5f,
                                     float w_anomaly = 0.3f,
                                     float w_time = 0.2f,
                                     float scope_weight = 0.5f) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (records_.empty()) return {};
        float qnorm = l2norm(query);
        std::vector<std::pair<float, size_t>> scores;
        scores.reserve(records_.size());
        for (size_t i = 0; i < records_.size(); ++i) {
            float age = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - records_[i].inserted_at).count();
            if (age > max_age_s) continue;
            float sim      = cosine(query, records_[i].embedding, qnorm);
            float recency  = expf(-age / std::max(recency_tau, 1.f));
            float final_s  = sim * w_sim
                           + records_[i].score * w_anomaly
                           + recency * w_time
                           + scope_weight;
            scores.emplace_back(final_s, i);
        }
        size_t take = std::min(k, scores.size());
        if (!take) return {};
        std::partial_sort(scores.begin(), scores.begin() + take, scores.end(),
                          [](auto& a, auto& b){ return a.first > b.first; });
                          
        // 1-hop Graph Expansion
        std::vector<size_t> expanded_indices;
        for (size_t i = 0; i < take; ++i) {
            size_t idx = scores[i].second;
            expanded_indices.push_back(idx);
            auto it = adjacency_list_.find(idx);
            if (it != adjacency_list_.end()) {
                for (size_t neighbor : it->second) {
                    expanded_indices.push_back(neighbor);
                }
            }
        }
        
        // Remove duplicates & sort
        std::sort(expanded_indices.begin(), expanded_indices.end());
        expanded_indices.erase(std::unique(expanded_indices.begin(), expanded_indices.end()), expanded_indices.end());
        
        std::vector<std::pair<float, size_t>> expanded_scores;
        for (size_t idx : expanded_indices) {
            float age = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - records_[idx].inserted_at).count();
            if (age > max_age_s) continue;
            float sim = cosine(query, records_[idx].embedding, qnorm);
            float recency = expf(-age / std::max(recency_tau, 1.f));
            float final_s = sim * w_sim + records_[idx].score * w_anomaly + recency * w_time + scope_weight;
            expanded_scores.emplace_back(final_s, idx);
        }
        
        std::sort(expanded_scores.begin(), expanded_scores.end(),
                  [](auto& a, auto& b){ return a.first > b.first; });
                  
        take = std::min(k, expanded_scores.size());
        std::vector<MemoryRecord> out;
        out.reserve(take);
        for (size_t i = 0; i < take; ++i) {
            auto rec = records_[expanded_scores[i].second];
            rec.score = expanded_scores[i].first;
            out.push_back(rec);
        }
        return out;
    }

    void sweep(float max_age_s) {
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();
        std::vector<size_t> keep_indices;
        for (size_t i = 0; i < records_.size(); ++i) {
            if (std::chrono::duration<float>(now - records_[i].inserted_at).count() <= max_age_s) {
                keep_indices.push_back(i);
            }
        }
        records_.erase(std::remove_if(records_.begin(), records_.end(),
            [&](const MemoryRecord& r){
                return std::chrono::duration<float>(now - r.inserted_at).count() > max_age_s;
            }), records_.end());
        // Simple sweep bypasses graph rebuild for speed in this context
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_); return records_.size();
    }

    void remove_by_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        records_.erase(std::remove_if(records_.begin(), records_.end(),
            [&](const MemoryRecord& r){ return r.key.ip == ip; }), records_.end());
    }

private:
    void evict() {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::pair<float, size_t>> confs;
        for (size_t i = 0; i < records_.size(); ++i) {
            confs.emplace_back(records_[i].score, i);
        }
        std::sort(confs.begin(), confs.end(), [](auto& a, auto& b){ return a.first > b.first; });
        size_t keep_count = max_size_ - (max_size_ / 4);
        std::vector<size_t> keep_indices;
        for (size_t i = 0; i < keep_count; ++i) keep_indices.push_back(confs[i].second);
        std::sort(keep_indices.begin(), keep_indices.end());
        rebuild_records(keep_indices);
    }

    void rebuild_records(const std::vector<size_t>& keep_indices) {
        std::vector<MemoryRecord> new_records;
        std::unordered_map<size_t, std::vector<size_t>> new_adj;
        std::unordered_map<size_t, size_t> old_to_new;
        
        for (size_t i = 0; i < keep_indices.size(); ++i) {
            old_to_new[keep_indices[i]] = i;
            new_records.push_back(std::move(records_[keep_indices[i]]));
        }
        
        for (auto& [old_idx, neighbors] : adjacency_list_) {
            if (old_to_new.count(old_idx)) {
                size_t new_idx = old_to_new[old_idx];
                for (size_t n : neighbors) {
                    if (old_to_new.count(n)) new_adj[new_idx].push_back(old_to_new[n]);
                }
            }
        }
        
        records_ = std::move(new_records);
        adjacency_list_ = std::move(new_adj);
    }

    static float l2norm(const Vec& v) {
        float s = 0.f; for (float x : v) s += x*x; return sqrtf(s + 1e-9f);
    }
    static float cosine(const Vec& a, const Vec& b, float anorm) {
        float dot = 0.f;
        for (size_t i = 0; i < kEmbeddingDim; ++i) dot += a[i]*b[i];
        return dot / (anorm * l2norm(b));
    }

    size_t                    max_size_ = 100000;
    float                     edge_threshold_ = 0.85f;
    uint64_t                  next_id_  = 1;
    std::vector<MemoryRecord> records_;
    std::unordered_map<size_t, std::vector<size_t>> adjacency_list_;
    mutable std::mutex        mu_;
};

// Rule table
struct Rule {
    uint32_t    id;
    std::string name;
    std::string pattern;
    float       threshold;
    Decision    action;
    bool        enabled  = true;
    uint32_t    priority = 0;
};

class RuleTable {
public:
    void add(Rule r) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_.push_back(std::move(r));
    }
    void remove(uint32_t id) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
            [id](const Rule& r){ return r.id == id; }), rules_.end());
    }
    void set_enabled(uint32_t id, bool enabled) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& r : rules_) if (r.id == id) r.enabled = enabled;
    }
    void replace(std::vector<Rule> new_rules) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_ = std::move(new_rules);
    }
    std::vector<std::string> match(float score, EventType, const std::string& src) const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::string> out;
        for (const auto& r : rules_) {
            if (!r.enabled) continue;
            if (score >= r.threshold) out.push_back(r.name);
            if (!r.pattern.empty() && src.find(r.pattern) != std::string::npos)
                out.push_back(r.name + ":ip");
        }
        return out;
    }
    std::vector<Rule> all() const {
        std::lock_guard<std::mutex> lk(mu_); return rules_;
    }
private:
    mutable std::mutex  mu_;
    std::vector<Rule>   rules_;
};

// Partitioned MemoryStore (§2.3)
struct MemoryStore {
    VectorGraphStore global_store;
    
    std::unordered_map<std::string, VectorGraphStore> host_store;
    std::unordered_map<std::string, VectorGraphStore> user_store;
    std::unordered_map<std::string, VectorGraphStore> ip_store;
    std::unordered_map<std::string, VectorGraphStore> session_store;
    std::unordered_map<std::string, VectorGraphStore> process_store;
    
    RuleTable rules;
    mutable std::shared_mutex host_mu;
    mutable std::shared_mutex global_mu;
};

// § 2.4 Write gating
inline bool should_write(float anomaly_score, float drift,
                          const RetrievedContext& ctx,
                          Decision decision,
                          const WritePolicy& pol) {
    if (anomaly_score >= pol.memory_force_gate)                           return true;
    if (anomaly_score >= pol.memory_write_gate)                           return true;
    if (pol.write_on_rule_match && !ctx.matched_rules.empty())            return true;
    if (pol.write_on_block     && decision == Decision::Block)            return true;
    if (pol.write_on_escalate  && decision == Decision::Escalate)         return true;
    if (pol.write_on_high_drift && drift >= pol.drift_write_threshold)    return true;
    return false;
}

// § 2.5 Scoped write
inline void write_record(MemoryStore& mem, MemoryRecord rec,
                          const MemoryKey& key, float anomaly_score,
                          const WritePolicy& pol) {
    rec.key = key;
    mem.ip_store[key.ip].insert(rec);
    if (!key.user.empty())
        mem.user_store[key.user].insert(rec);
    if (anomaly_score >= 0.50f && !key.host.empty())
        mem.host_store[key.host].insert(rec);
    if (anomaly_score >= pol.memory_force_gate) {
        std::unique_lock lk(mem.global_mu);
        mem.global_store.insert(rec);
    }
    if (!key.session.empty())
        mem.session_store[key.session].insert(rec);
    if (!key.process.empty())
        mem.process_store[key.process].insert(rec);
}

// Retriever (§2.7–2.14)
class Retriever {
public:
    explicit Retriever(MemoryStore&          mem,
                       RetrievalTimeConfig   time_cfg  = {},
                       RetrievalWeights      weights   = {},
                       ForceRetrievalConfig  force_cfg = {})
        : mem_(mem), time_cfg_(time_cfg), weights_(weights), force_cfg_(force_cfg) {}

    RetrievedContext retrieve(const LocalState&   ls,
                              const SegmentState& ss,
                              const GlobalState&  gs,
                              const Event&        ev) const {
        (void)ss;  // segment state available for future scope weighting
        RetrievedContext ctx;
        MemoryKey key = key_from_event(ev);

        (void)(force_cfg_.force_retrieve ||
               force_cfg_.force_on_block ||
               gs.drift_score > force_cfg_.drift_force_threshold);  // evaluated via retrieve logic below

        float max_age  = time_cfg_.retrieval_max_age_s;
        float tau      = time_cfg_.recency_tau;
        float ws = weights_.w_sim, wa = weights_.w_anomaly, wt = weights_.w_time;

        // Scope order: ip → user → session → host → global (§2.7)
        auto merge = [&](const std::vector<MemoryRecord>& hits) {
            for (auto& h : hits) {
                bool dup = false;
                for (auto& e : ctx.records) if (e.id == h.id) { dup = true; break; }
                if (!dup) ctx.records.push_back(h);
                ctx.similarity_max = std::max(ctx.similarity_max, h.score);
            }
        };

        if (mem_.ip_store.count(key.ip))
            merge(mem_.ip_store.at(key.ip).search(ls.embedding, 3, max_age, tau, ws, wa, wt, 1.0f));
        if (!key.user.empty() && mem_.user_store.count(key.user))
            merge(mem_.user_store.at(key.user).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.9f));
        if (!key.session.empty() && mem_.session_store.count(key.session))
            merge(mem_.session_store.at(key.session).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.85f));
        if (!key.host.empty() && mem_.host_store.count(key.host))
            merge(mem_.host_store.at(key.host).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.7f));

        {
            std::shared_lock glk(mem_.global_mu);
            auto ghits = mem_.global_store.search(ls.embedding, 1, max_age, tau, ws, wa, wt, 0.5f);
            merge(ghits);
        }

        // Sort by score, cap at kTopKRetrieval
        std::sort(ctx.records.begin(), ctx.records.end(),
                  [](const MemoryRecord& a, const MemoryRecord& b){ return a.score > b.score; });
        if (ctx.records.size() > kTopKRetrieval)
            ctx.records.resize(kTopKRetrieval);

        // Rule matching
        ctx.matched_rules = mem_.rules.match(ls.anomaly_score, ev.type, ev.source);
        return ctx;
    }

    void write(const LocalState& ls, const Event& ev,
               float anomaly_score, Decision decision,
               const RetrievedContext& ctx,
               const WritePolicy& pol) {
        if (!should_write(anomaly_score, 0.f, ctx, decision, pol)) return;
        MemoryRecord rec;
        rec.embedding   = ls.embedding;
        rec.score       = anomaly_score;
        rec.label       = "auto";
        rec.raw_summary = "src=" + ev.source;
        write_record(mem_, rec, key_from_event(ev), anomaly_score, pol);
    }

    void store_anomaly(const LocalState& ls, const std::string& label,
                       float score, const std::string& summary,
                       const MemoryKey& key = {}) {
        MemoryRecord r;
        r.embedding   = ls.embedding;
        r.score       = score;
        r.label       = label;
        r.raw_summary = summary;
        r.key         = key;
        mem_.global_store.insert(r);
        if (!key.ip.empty()) mem_.ip_store[key.ip].insert(r);
    }

    enum class CleanupReason { SessionEnd, StateExpired, HostRemoved, Manual };

    void cleanup(const MemoryKey& key, CleanupReason reason) {
        if (!key.ip.empty())      mem_.ip_store.erase(key.ip);
        if (!key.session.empty()) mem_.session_store.erase(key.session);
        if (reason == CleanupReason::HostRemoved && !key.host.empty())
            mem_.host_store.erase(key.host);
        if (reason == CleanupReason::Manual) {
            if (!key.user.empty())    mem_.user_store.erase(key.user);
            if (!key.process.empty()) mem_.process_store.erase(key.process);
        }
    }

    void sweep(const MemoryCleanupConfig& cfg) {
        mem_.global_store.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.ip_store)      vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.host_store)     vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.user_store)     vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.session_store)  vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.process_store)  vs.sweep(cfg.record_ttl_s);
    }

private:
    MemoryStore&         mem_;
    RetrievalTimeConfig  time_cfg_;
    RetrievalWeights     weights_;
    ForceRetrievalConfig force_cfg_;
};

}  // namespace ids

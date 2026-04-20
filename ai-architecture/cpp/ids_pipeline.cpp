/**
 * ids_pipeline.cpp — pybind11 bindings for the C++ IDS pipeline.
 *
 * Exposes to Python:
 *   ids_pipeline.IDS          — main pipeline (thread-safe ingest)
 *   ids_pipeline.Event        — input event
 *   ids_pipeline.PayloadFeatures
 *   ids_pipeline.Alert        — decision callback payload
 *   ids_pipeline.Decision     — enum: Ignore/Log/Alert/Block/Escalate
 *   ids_pipeline.EventType    — enum
 *   ids_pipeline.IDSConfig    — full config (all sub-structs exposed)
 *   ids_pipeline.PipelineState— ingest() return value
 *
 * Usage from Python:
 *   import ids_pipeline as cpp
 *
 *   cfg = cpp.IDSConfig()
 *   ids = cpp.IDS(cfg)
 *   ids.on_alert(lambda a: print(a.decision, a.confidence))
 *
 *   ev = cpp.Event()
 *   ev.source = "1.2.3.4"
 *   ev.destination = "10.0.0.1"
 *   ev.type = cpp.EventType.NetworkPacket
 *   ev.payload.bytes_in  = 1400
 *   ev.payload.rate_hz   = 5000.0
 *   ev.payload.entropy   = 0.9
 *   ev.payload.flags     = 0x02
 *   ev.payload.port_dst  = 80
 *   ev.payload.protocol  = 6
 *
 *   state = ids.ingest(ev)
 *   print(state.local.anomaly_score)
 */

#include <pybind11/pybind11.h>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include <pybind11/chrono.h>

#include "ids.hpp"
#include "ids_ebpf.hpp"

namespace py = pybind11;
using namespace ids;

// Helper: convert Alert to a plain Python dict for easy dashboard consumption
static py::dict alert_to_dict(const Alert& a) {
    py::dict d;
    d["decision"]     = static_cast<int>(a.decision);
    d["confidence"]   = a.confidence;
    d["attack_class"] = a.attack_class;
    d["explanation"]  = a.explanation;
    d["source"]       = a.source;
    d["destination"]  = a.destination;
    d["corr_score"]   = a.trace.corr_score;
    d["fused_score"]  = a.trace.fused_score;
    d["drift_score"]  = a.trace.drift_score;
    d["campaign_id"]  = a.trace.campaign_id;
    return d;
}

PYBIND11_MODULE(ids_pipeline, m) {
    m.doc() = "C++ IDS pipeline — zero-GIL hot path via pybind11";

    // ── Enums ────────────────────────────────────────────────────────────────
    py::enum_<Decision>(m, "Decision")
        .value("Ignore",   Decision::Ignore)
        .value("Log",      Decision::Log)
        .value("Alert",    Decision::Alert)
        .value("Block",    Decision::Block)
        .value("Escalate", Decision::Escalate);

    py::enum_<EventType>(m, "EventType")
        .value("NetworkPacket", EventType::NetworkPacket)
        .value("SysLog",        EventType::SysLog)
        .value("ProcessEvent",  EventType::ProcessEvent)
        .value("AuthEvent",     EventType::AuthEvent)
        .value("FileAccess",    EventType::FileAccess)
        .value("ApiCall",       EventType::ApiCall)
        .value("Signal",        EventType::Signal)
        .value("Unknown",       EventType::Unknown)
        .export_values();

    // ── PayloadFeatures ──────────────────────────────────────────────────────
    py::class_<PayloadFeatures>(m, "PayloadFeatures")
        .def(py::init<>())
        .def_readwrite("bytes_in",  &PayloadFeatures::bytes_in)
        .def_readwrite("bytes_out", &PayloadFeatures::bytes_out)
        .def_readwrite("port_src",  &PayloadFeatures::port_src)
        .def_readwrite("port_dst",  &PayloadFeatures::port_dst)
        .def_readwrite("protocol",  &PayloadFeatures::protocol)
        .def_readwrite("flags",     &PayloadFeatures::flags)
        .def_readwrite("entropy",   &PayloadFeatures::entropy)
        .def_readwrite("rate_hz",   &PayloadFeatures::rate_hz);

    // ── Event ────────────────────────────────────────────────────────────────
    py::class_<Event>(m, "Event")
        .def(py::init<>())
        .def_readwrite("source",      &Event::source)
        .def_readwrite("destination", &Event::destination)
        .def_readwrite("type",        &Event::type)
        .def_readwrite("payload",     &Event::payload)
        .def_readwrite("metadata",    &Event::metadata);

    // ── LocalState ───────────────────────────────────────────────────────────
    py::class_<LocalState>(m, "LocalState")
        .def_readonly("anomaly_score", &LocalState::anomaly_score)
        .def_readonly("entropy",       &LocalState::entropy)
        .def_readonly("burst_metric",  &LocalState::burst_metric)
        .def_property_readonly("embedding", [](const LocalState& ls) {
            return std::vector<float>(ls.embedding.begin(), ls.embedding.end());
        });

    // ── SegmentState ─────────────────────────────────────────────────────────
    py::class_<SegmentState>(m, "SegmentState")
        .def_readonly("anomaly_trend",  &SegmentState::anomaly_trend)
        .def_readonly("rate_mean",      &SegmentState::rate_mean)
        .def_readonly("error_freq",     &SegmentState::error_freq)
        .def_readonly("dominant_type",  &SegmentState::dominant_type);

    // ── GlobalState ──────────────────────────────────────────────────────────
    py::class_<GlobalState>(m, "GlobalState")
        .def_readonly("anomaly_history", &GlobalState::anomaly_history)
        .def_readonly("drift_score",     &GlobalState::drift_score);

    // ── PipelineState ────────────────────────────────────────────────────────
    py::class_<PipelineState>(m, "PipelineState")
        .def_readonly("local",   &PipelineState::local)
        .def_readonly("segment", &PipelineState::segment)
        .def_readonly("global_", &PipelineState::global)
        // Convenience dict for the existing Python dashboard
        .def("to_dict", [](const PipelineState& ps) {
            py::dict d;
            d["anomaly_score"]   = ps.local.anomaly_score;
            d["entropy"]         = ps.local.entropy;
            d["burst_metric"]    = ps.local.burst_metric;
            d["anomaly_trend"]   = ps.segment.anomaly_trend;
            d["rate_mean"]       = ps.segment.rate_mean;
            d["anomaly_history"] = ps.global.anomaly_history;
            d["drift_score"]     = ps.global.drift_score;
            return d;
        });

    // ── Alert ────────────────────────────────────────────────────────────────
    py::class_<Alert>(m, "Alert")
        .def_readonly("decision",     &Alert::decision)
        .def_readonly("confidence",   &Alert::confidence)
        .def_readonly("attack_class", &Alert::attack_class)
        .def_readonly("explanation",  &Alert::explanation)
        .def_readonly("source",       &Alert::source)
        .def_readonly("destination",  &Alert::destination)
        .def("to_dict", [](const Alert& a) { return alert_to_dict(a); });

    // ── Config sub-structs (expose the most useful knobs) ────────────────────
    py::class_<DecisionThresholds>(m, "DecisionThresholds")
        .def(py::init<>())
        .def_readwrite("ignore_threshold", &DecisionThresholds::ignore_threshold)
        .def_readwrite("log_threshold",    &DecisionThresholds::log_threshold)
        .def_readwrite("alert_threshold",  &DecisionThresholds::alert_threshold)
        .def_readwrite("block_threshold",  &DecisionThresholds::block_threshold);

    py::class_<ScoreFusionWeights>(m, "ScoreFusionWeights")
        .def(py::init<>())
        .def_readwrite("w_local",     &ScoreFusionWeights::w_local)
        .def_readwrite("w_segment",   &ScoreFusionWeights::w_segment)
        .def_readwrite("w_history",   &ScoreFusionWeights::w_history)
        .def_readwrite("w_drift",     &ScoreFusionWeights::w_drift)
        .def_readwrite("w_retrieval", &ScoreFusionWeights::w_retrieval)
        .def_readwrite("w_rule",      &ScoreFusionWeights::w_rule);

    py::class_<WritePolicy>(m, "WritePolicy")
        .def(py::init<>())
        .def_readwrite("memory_write_gate", &WritePolicy::memory_write_gate)
        .def_readwrite("memory_force_gate", &WritePolicy::memory_force_gate)
        .def_readwrite("write_on_block",    &WritePolicy::write_on_block)
        .def_readwrite("write_on_escalate", &WritePolicy::write_on_escalate);

    py::class_<ReasoningGateConfig>(m, "ReasoningGateConfig")
        .def(py::init<>())
        .def_readwrite("gate_threshold", &ReasoningGateConfig::gate_threshold);

    // ── IDSConfig ────────────────────────────────────────────────────────────
    py::class_<IDSConfig>(m, "IDSConfig")
        .def(py::init<>())
        .def_readwrite("thresholds",   &IDSConfig::thresholds)
        .def_readwrite("fusion",       &IDSConfig::fusion)
        .def_readwrite("write_policy", &IDSConfig::write_policy)
        .def_readwrite("gate",         &IDSConfig::gate);

    // ── IDS (main pipeline) ──────────────────────────────────────────────────
    py::class_<IDS>(m, "IDS")
        .def(py::init<const IDSConfig&>(), py::arg("cfg") = IDSConfig{})

        // Callbacks — called from the pipeline thread, so release the GIL
        .def("on_alert", [](IDS& ids, py::object cb) {
            ids.on_alert([cb](const Alert& a) {
                py::gil_scoped_acquire gil;
                cb(a);
            });
        })
        .def("on_block", [](IDS& ids, py::object cb) {
            ids.on_block([cb](const std::string& src) {
                py::gil_scoped_acquire gil;
                cb(src);
            });
        })
        .def("on_escalate", [](IDS& ids, py::object cb) {
            ids.on_escalate([cb](const Alert& a) {
                py::gil_scoped_acquire gil;
                cb(a);
            });
        })

        // ingest() — releases GIL so other Python threads run during C++ work
        .def("ingest", [](IDS& ids, const Event& ev) {
            py::gil_scoped_release release;
            return ids.ingest(ev);
        })

        // Convenience: accept the existing Python pipeline dict directly
        .def("ingest_dict", [](IDS& ids, py::dict d) {
            Event ev;
            ev.type = EventType::NetworkPacket;
            if (d.contains("source"))      ev.source      = d["source"].cast<std::string>();
            if (d.contains("destination")) ev.destination = d["destination"].cast<std::string>();
            if (d.contains("payload")) {
                py::dict p = d["payload"].cast<py::dict>();
                if (p.contains("bytes_in"))  ev.payload.bytes_in  = p["bytes_in"].cast<uint32_t>();
                if (p.contains("bytes_out")) ev.payload.bytes_out = p["bytes_out"].cast<uint32_t>();
                if (p.contains("port_src"))  ev.payload.port_src  = p["port_src"].cast<uint16_t>();
                if (p.contains("port_dst"))  ev.payload.port_dst  = p["port_dst"].cast<uint16_t>();
                if (p.contains("protocol"))  ev.payload.protocol  = p["protocol"].cast<uint8_t>();
                if (p.contains("flags"))     ev.payload.flags     = p["flags"].cast<uint8_t>();
                if (p.contains("entropy"))   ev.payload.entropy   = p["entropy"].cast<float>();
                if (p.contains("rate_hz"))   ev.payload.rate_hz   = p["rate_hz"].cast<float>();
            }
            py::gil_scoped_release release;
            return ids.ingest(ev);
        })

        .def("ingest_batch", [](IDS& ids, const std::vector<Event>& evs) {
            py::gil_scoped_release release;
            ids.ingest_batch(evs);
        })

        .def("memory_size",    &IDS::memory_size)
        .def("global_state",   &IDS::global_state)
        .def("segment_state",  &IDS::segment_state)
        .def("reset",          &IDS::reset)
        .def("save_state",     &IDS::save_state)
        .def("load_state",     &IDS::load_state)

        .def("metrics", [](const IDS& ids) {
            const auto& m = ids.metrics();
            py::dict d;
            d["events_total"]      = m.events_total.load();
            d["alerts_total"]      = m.alerts_total.load();
            d["blocks_total"]      = m.blocks_total.load();
            d["escalations_total"] = m.escalations_total.load();
            d["reasoning_calls"]   = m.reasoning_calls.load();
            d["memory_writes"]     = m.memory_writes.load();
            d["faults_total"]      = m.faults_total.load();
            return d;
        })

        .def("latency_stats", [](const IDS& ids) {
            auto l = ids.latency_stats();
            py::dict d;
            d["l0_avg_us"]        = l.l0_avg_us;
            d["l1_avg_us"]        = l.l1_avg_us;
            d["l2_avg_us"]        = l.l2_avg_us;
            d["retrieval_avg_us"] = l.retrieval_avg_us;
            d["reasoning_avg_us"] = l.reasoning_avg_us;
            d["total_avg_us"]     = l.total_avg_us;
            d["total_p99_us"]     = l.total_p99_us;
            return d;
        })

        .def("health", [](const IDS& ids) {
            const auto& h = ids.health();
            py::dict d;
            d["panic_mode"]      = h.panic_mode;
            d["numeric_faults"]  = h.numeric_faults.load();
            d["reasoning_fails"] = h.reasoning_fails.load();
            d["retrieval_fails"] = h.retrieval_fails.load();
            return d;
        })

        .def("save_config", &IDS::save_config)
        .def("hot_reload_config", [](IDS& ids, IDSConfig cfg) {
            return ids.hot_reload_config(cfg);
        })
        .def("rollback_config", &IDS::rollback_config)
        .def("active_campaigns", &IDS::active_campaigns);

    // ── eBPF Structures ─────────────────────────────────────────────────────
    py::class_<EBPFPacketEvent>(m, "EBPFPacketEvent")
        .def(py::init<>())
        .def_readwrite("src_ip",       &EBPFPacketEvent::src_ip)
        .def_readwrite("dst_ip",       &EBPFPacketEvent::dst_ip)
        .def_readwrite("src_port",     &EBPFPacketEvent::src_port)
        .def_readwrite("dst_port",     &EBPFPacketEvent::dst_port)
        .def_readwrite("protocol",     &EBPFPacketEvent::protocol)
        .def_readwrite("flags",        &EBPFPacketEvent::flags)
        .def_readwrite("payload_len",  &EBPFPacketEvent::payload_len)
        .def_readwrite("timestamp_ns", &EBPFPacketEvent::timestamp_ns)
        .def_readwrite("action",       &EBPFPacketEvent::action);

    py::class_<EBPFStats>(m, "EBPFStats")
        .def(py::init<>())
        .def_readwrite("packets_processed", &EBPFStats::packets_processed)
        .def_readwrite("packets_blocked",   &EBPFStats::packets_blocked)
        .def_readwrite("packets_allowed",   &EBPFStats::packets_allowed)
        .def_readwrite("rate_limited",      &EBPFStats::rate_limited)
        .def_readwrite("parse_errors",      &EBPFStats::parse_errors)
        .def("block_rate",  &EBPFStats::block_rate)
        .def("error_rate",  &EBPFStats::error_rate);

    py::class_<EBPFManager>(m, "EBPFManager")
        .def(py::init<const std::string&, const std::string&>(),
             py::arg("interface") = "eth0",
             py::arg("ebpf_obj_path") = "")
        .def("initialize", &EBPFManager::initialize)
        .def("start", [](EBPFManager& mgr, py::object cb) {
            mgr.start([cb](const EBPFPacketEvent& ev) {
                py::gil_scoped_acquire gil;
                cb(ev);
            });
        })
        .def("stop", &EBPFManager::stop)
        .def("is_running", &EBPFManager::is_running)
        .def("block_ip", &EBPFManager::block_ip)
        .def("unblock_ip", &EBPFManager::unblock_ip)
        .def("get_stats", &EBPFManager::get_stats)
        .def("get_blocklist_size", &EBPFManager::get_blocklist_size)
        .def("clear_blocklist", &EBPFManager::clear_blocklist)
        .def("is_blocked", &EBPFManager::is_blocked);

    py::class_<EBPFAwareIDS>(m, "EBPFAwareIDS")
        .def(py::init<const std::string&, const std::string&, bool>(),
             py::arg("interface") = "eth0",
             py::arg("ebpf_obj_path") = "",
             py::arg("enabled") = true)
        .def("initialize", &EBPFAwareIDS::initialize)
        .def("start", [](EBPFAwareIDS& ids, py::object cb) {
            ids.start([cb](const EBPFPacketEvent& ev) {
                py::gil_scoped_acquire gil;
                cb(ev);
            });
        })
        .def("stop", &EBPFAwareIDS::stop)
        .def("is_running", &EBPFAwareIDS::is_running)
        .def("block_ip", &EBPFAwareIDS::block_ip)
        .def("unblock_ip", &EBPFAwareIDS::unblock_ip)
        .def("get_stats", &EBPFAwareIDS::get_stats)
        .def("get_blocklist_size", &EBPFAwareIDS::get_blocklist_size)
        .def("clear_blocklist", &EBPFAwareIDS::clear_blocklist)
        .def("is_enabled", &EBPFAwareIDS::is_enabled);

    // ── Module-level helpers ─────────────────────────────────────────────────
    m.def("decision_name", [](Decision d) -> std::string {
        switch (d) {
            case Decision::Ignore:   return "Ignore";
            case Decision::Log:      return "Log";
            case Decision::Alert:    return "Alert";
            case Decision::Block:    return "Block";
            case Decision::Escalate: return "Escalate";
        }
        return "Unknown";
    });

    // Build a C++ Event from the existing Python pipeline dict format
    m.def("make_event", [](py::dict d) {
        Event ev;
        ev.type = EventType::NetworkPacket;
        if (d.contains("source"))      ev.source      = d["source"].cast<std::string>();
        if (d.contains("destination")) ev.destination = d["destination"].cast<std::string>();
        if (d.contains("payload")) {
            py::dict p = d["payload"].cast<py::dict>();
            if (p.contains("bytes_in"))  ev.payload.bytes_in  = p["bytes_in"].cast<uint32_t>();
            if (p.contains("bytes_out")) ev.payload.bytes_out = p["bytes_out"].cast<uint32_t>();
            if (p.contains("port_src"))  ev.payload.port_src  = p["port_src"].cast<uint16_t>();
            if (p.contains("port_dst"))  ev.payload.port_dst  = p["port_dst"].cast<uint16_t>();
            if (p.contains("protocol"))  ev.payload.protocol  = p["protocol"].cast<uint8_t>();
            if (p.contains("flags"))     ev.payload.flags     = p["flags"].cast<uint8_t>();
            if (p.contains("entropy"))   ev.payload.entropy   = p["entropy"].cast<float>();
            if (p.contains("rate_hz"))   ev.payload.rate_hz   = p["rate_hz"].cast<float>();
        }
        if (d.contains("metadata")) {
            py::dict md = d["metadata"].cast<py::dict>();
            for (auto item : md) {
                try {
                    ev.metadata[item.first.cast<std::string>()] =
                        item.second.cast<std::string>();
                } catch (...) {}
            }
        }
        return ev;
    });
}

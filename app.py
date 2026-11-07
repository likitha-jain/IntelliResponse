"""IntelliResponse — a SOC triage agent that learns from every analyst verdict.

Run with:
    streamlit run app.py
"""
from __future__ import annotations

import hmac
import json
import os
import time
from datetime import date

import pandas as pd
import streamlit as st

from agent import (
    csv_safe,
    Memory,
    ACTION_TEXT,
    CATEGORY_LABELS,
    VERDICT_LABELS,
    investigate,
    learning_stats,
    load_history,
    record_outcome,
    reflect_view,
    report_json,
    report_markdown,
)
from config import get_settings
from data import SAMPLE_ALERTS
from theme import (
    action_row,
    badge,
    callout,
    chip,
    empty_state,
    esc,
    flow,
    hero,
    impact,
    incident_card,
    inject_css,
    kpi,
    risk_badge,
    section,
)

# =============================================================================
# Page setup and state
# =============================================================================

st.set_page_config(
    page_title="IntelliResponse · SOC memory",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject_css()
cfg = get_settings()
S = st.session_state

# ---- Optional access gate -------------------------------------------------------
# Set IR_UI_PASSWORD to require a password before anything (including the
# memory-reset control) is rendered. For internet exposure, also put the app behind
# an authenticating reverse proxy / SSO.
_UI_PASSWORD = (os.getenv("IR_UI_PASSWORD") or "").strip()
if _UI_PASSWORD and not S.get("_ui_authed"):
    st.markdown("### 🛡️ IntelliResponse · sign in")
    if S.get("_ui_attempts", 0) >= 10:
        st.error("Too many failed attempts for this session. Restart the session to retry.")
        st.stop()
    _entered = st.text_input("Access password", type="password")
    if _entered:
        if hmac.compare_digest(_entered.encode("utf-8"), _UI_PASSWORD.encode("utf-8")):
            S["_ui_authed"] = True
            S["_ui_attempts"] = 0
            st.rerun()
        else:
            S["_ui_attempts"] = S.get("_ui_attempts", 0) + 1
            time.sleep(1.0)
            st.error("Incorrect password.")
    st.stop()


def sget(key, default=None):
    return S[key] if key in S else default


def spop(key, default=None):
    if key in S:
        value = S[key]
        del S[key]
        return value
    return default


if "mem" not in S:
    S["mem"] = Memory()
mem: Memory = S["mem"]

SAMPLE_KEYS = list(SAMPLE_ALERTS)
A_KEY = next((k for k in SAMPLE_KEYS if k.startswith("A")), SAMPLE_KEYS[0])
B_KEY = next((k for k in SAMPLE_KEYS if k.startswith("B")), SAMPLE_KEYS[0])
C_KEY = next((k for k in SAMPLE_KEYS if k.startswith("C")), SAMPLE_KEYS[0])

# Pending demo actions are applied before any widget is instantiated, which
# avoids Streamlit's "cannot modify a widget key after instantiation" rule.
pending = spop("_pending", None)
if pending:
    if pending.get("reset"):
        mem.reset()
        S["bootstrapped"] = True
        S["history_slider"] = 0
        S["rep"] = None
        S["previous_rep"] = None
        S["last_saved"] = None
        S["reflection"] = None
    if "memory_enabled" in pending:
        S["memory_enabled"] = bool(pending["memory_enabled"])
    if "live_osint" in pending:
        S["live_osint"] = bool(pending["live_osint"])
    load_n = pending.get("load")
    if load_n is not None:
        with st.spinner("Loading incident history into memory…"):
            load_history(mem, int(load_n))
        S["history_slider"] = int(load_n)
        S["bootstrapped"] = True
    if "pick" in pending:
        S["pick_alert"] = pending["pick"]
    if "raw" in pending:
        S["raw_alert"] = pending["raw"]
    if pending.get("clear_report"):
        S["rep"] = None
        S["previous_rep"] = None
        S["last_saved"] = None
    if pending.get("auto_run"):
        S["auto_run"] = True
    if "nav" in pending:
        S["nav"] = pending["nav"]

# First run: seed the demo history and immediately show the money shot.
if "bootstrapped" not in S:
    S["bootstrapped"] = True
    if not mem.incidents() and int(mem.meta.get("loaded", 0) or 0) == 0:
        with st.spinner("Seeding the incident memory bank…"):
            load_history(mem, cfg.demo_seed_count)
    S["auto_run"] = True

defaults = {
    "nav": "Triage",
    "memory_enabled": True,
    "live_osint": cfg.live_osint,
    "pick_alert": B_KEY,
    "raw_alert": SAMPLE_ALERTS.get(B_KEY, ""),
    "history_slider": int(mem.meta.get("loaded", 0) or 0),
    "rep": None,
    "previous_rep": None,
    "last_saved": None,
    "reflection": None,
    "auto_run": False,
    "flash": None,
}
for key, value in defaults.items():
    if key not in S:
        S[key] = value


def _sample_changed() -> None:
    pick = sget("pick_alert")
    if pick in SAMPLE_ALERTS:
        S["raw_alert"] = SAMPLE_ALERTS[pick]


def _load_sample() -> None:
    pick = sget("pick_alert")
    if pick in SAMPLE_ALERTS:
        S["raw_alert"] = SAMPLE_ALERTS[pick]


def _request_reset() -> None:
    S["_pending"] = {
        "reset": True,
        "load": 0,
        "clear_report": True,
        "nav": "Triage",
        "auto_run": False,
    }


def _demo_step(step: int) -> None:
    if step == 1:
        S["_pending"] = {
            "reset": True,
            "load": 0,
            "memory_enabled": False,
            "pick": B_KEY,
            "raw": SAMPLE_ALERTS[B_KEY],
            "nav": "Triage",
            "clear_report": True,
            "auto_run": True,
        }
    elif step == 2:
        S["_pending"] = {
            "load": 20,
            "memory_enabled": True,
            "pick": B_KEY,
            "raw": SAMPLE_ALERTS[B_KEY],
            "nav": "Triage",
            "clear_report": True,
            "auto_run": True,
        }
    elif step == 3:
        S["_pending"] = {
            "memory_enabled": True,
            "pick": A_KEY,
            "raw": SAMPLE_ALERTS[A_KEY],
            "nav": "Triage",
            "clear_report": True,
            "auto_run": True,
        }
    elif step == 4:
        S["_pending"] = {
            "memory_enabled": True,
            "pick": C_KEY,
            "raw": SAMPLE_ALERTS[C_KEY],
            "nav": "Triage",
            "clear_report": True,
            "auto_run": True,
        }


def _pick_sample(key: str) -> None:
    S["pick_alert"] = key
    S["raw_alert"] = SAMPLE_ALERTS.get(key, "")
    S["rep"] = None
    S["previous_rep"] = None
    S["last_saved"] = None
    S["auto_run"] = True


def run_investigation(raw: str) -> None:
    if not raw or not raw.strip():
        st.toast("Paste an alert or choose a sample first.")
        return
    with st.spinner("Recalling memory · enriching OSINT · calibrating risk…"):
        report = investigate(
            raw,
            mem,
            use_memory=bool(sget("memory_enabled", True)),
            live=bool(sget("live_osint", False)),
        )
    S["rep"] = report
    S["rep_raw"] = raw
    S["last_saved"] = None
    S["previous_rep"] = None


# =============================================================================
# Sidebar
# =============================================================================

with st.sidebar:
    st.markdown(
        '<div class="ir-brand"><div class="ir-logo">🛡️</div>'
        '<div><div class="ir-brand-name">IntelliResponse</div>'
        '<div class="ir-brand-sub">SOC memory console</div></div></div>',
        unsafe_allow_html=True,
    )
    st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
    st.radio(
        "Navigation",
        ["Triage", "Learning", "History", "Memory", "Demo"],
        key="nav",
        label_visibility="collapsed",
    )
    st.divider()

    status = mem.status()
    status_tone = "ok" if status["connected"] else "warn"
    status_label = "Hindsight connected" if status["connected"] else "Local demo memory"
    st.markdown(
        f'<div class="ir-card" style="padding:13px 14px">'
        f'<div style="display:flex;justify-content:space-between;align-items:center;gap:8px">'
        f'<span style="font-size:12px;font-weight:750">{esc(status_label)}</span>'
        f'{badge("ONLINE" if status["connected"] else "FALLBACK", status_tone)}</div>'
        f'<div style="color:var(--ir-muted);font-size:11px;margin-top:7px;line-height:1.4">'
        f'bank <code>{esc(status["bank"])}</code><br/>{esc(status.get("api_version") or "durable local mirror")}</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

    st.toggle(
        "Memory ON",
        key="memory_enabled",
        help="OFF = stateless analyst. ON = recall analyst verdicts, false-positive sources and effective actions.",
    )
    st.toggle(
        "Live OSINT",
        key="live_osint",
        help="CISA KEV and AlienVault OTX when available. Falls back to cached samples automatically.",
    )

    loaded = int(mem.meta.get("loaded", 0) or 0)
    n = st.slider(
        "Past incidents loaded",
        min_value=0,
        max_value=20,
        value=loaded,
        key="history_slider",
        help="Move this during the demo to show the learning curve.",
    )
    if n > loaded:
        with st.spinner("Retaining incidents in memory…"):
            load_history(mem, n)
        st.rerun()
    elif n < loaded:
        st.caption("Memory can't un-happen. Use Reset for a clean demo.")

    st.caption(
        f"{len(mem.incidents())} incidents · {status['verdicts']} verdicts · "
        f"{status['local_memories']} memories"
    )
    st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
    st.button("Reset demo memory", on_click=_request_reset, use_container_width=True)
    if mem.last_reset_note:
        st.caption(mem.last_reset_note)
    st.divider()
    st.caption("Defensive use only. Public/demo data only. The agent recommends; it never executes.")
    st.markdown(
        "[Hindsight docs](https://hindsight.vectorize.io/) · "
        "[Cloud](https://ui.hindsight.vectorize.io/) · "
        "[GitHub](https://github.com/vectorize-io/hindsight)"
    )


# =============================================================================
# Shared report renderer
# =============================================================================


def render_report(report: dict) -> None:
    p = report["alert"]
    delta = report["delta"]
    conf = int(report["confidence"] * 100)
    base_conf = int(report["baseline"]["confidence"] * 100)
    recall_source = report.get("recall", {}).get("source", "local mirror")
    remote_hits = report.get("recall", {}).get("remote_results", 0)

    cols = st.columns(4)
    with cols[0]:
        st.markdown(
            kpi(
                "Risk",
                report["risk"],
                f"{conf}% confidence · baseline {base_conf}%",
                {"HIGH": "danger", "MEDIUM": "warn", "LOW": "ok"}.get(report["risk"], "neutral"),
            ),
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            kpi(
                "Similar memories",
                str(len(report["similar"])),
                f"{recall_source}" + (f" · {remote_hits} remote hits" if remote_hits else ""),
                "info",
            ),
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            kpi(
                "Memory impact",
                f"{delta['confidence_delta']:+.0%}",
                delta["impact"],
                "ok" if delta["confidence_delta"] < 0 else "warn" if delta["changed_risk"] else "info",
            ),
            unsafe_allow_html=True,
        )
    with cols[3]:
        st.markdown(
            kpi(
                "Analyst time",
                "18 min",
                "estimated saved per auto-downgraded false positive",
                "neutral",
            ),
            unsafe_allow_html=True,
        )

    st.markdown(
        impact(report["baseline"], report, delta, bool(report["memory_used"])),
        unsafe_allow_html=True,
    )

    with st.container(border=True):
        st.markdown('<div class="ir-card-title">Incident summary</div>', unsafe_allow_html=True)
        st.markdown(report["summary"])
        engine = report.get("llm_model") or "deterministic template (no LLM key)"
        st.caption(f"Engine: {engine} · {report['elapsed_ms']} ms · memory {report['memory_backend']}")

    left, right = st.columns([1.12, 1.0], gap="large")

    with left:
        with st.container(border=True):
            st.markdown('<div class="ir-card-title">Extracted indicators</div>', unsafe_allow_html=True)
            st.markdown(
                f"- **Source IP** `{p.get('source_ip')}` · *{p.get('scope')}*\n"
                f"- **Service** {p.get('service', '').upper()} · **Category** "
                f"{CATEGORY_LABELS.get(p.get('category'), p.get('category'))}\n"
                f"- **Target host** `{p.get('target_host')}`\n"
                f"- **Failures** {p.get('failures')} · **Events** {p.get('events')}\n"
                f"- **Domains** {', '.join(f'`{d}`' for d in p.get('domains') or []) or 'none'}\n"
                f"- **Hashes** {', '.join(f'`{h}`' for h in p.get('hashes') or []) or 'none'}"
            )

        with st.container(border=True):
            st.markdown('<div class="ir-card-title">MITRE ATT&amp;CK</div>', unsafe_allow_html=True)
            if report["mitre"]:
                st.markdown(
                    "".join(chip(name, tech) for tech, name in report["mitre"]),
                    unsafe_allow_html=True,
                )
            else:
                st.caption("No mapping for this category yet.")

        with st.container(border=True):
            st.markdown('<div class="ir-card-title">OSINT enrichment</div>', unsafe_allow_html=True)
            st.caption(report["osint"]["source"])
            ip = report["osint"].get("ip")
            if ip:
                st.markdown(
                    f"- IP `{p.get('source_ip')}`: **{ip.get('pulses', 0)}** reports · "
                    f"tags {ip.get('tags') or []}"
                )
            for domain in report["osint"].get("domains") or []:
                st.markdown(
                    f"- Domain `{domain['domain']}`: **{domain.get('pulses', 0)}** reports · "
                    f"tags {domain.get('tags') or []}"
                )
            for vuln in report["osint"].get("vulns") or []:
                st.markdown(
                    f"- **{vuln['cve']}** on `{vuln['host']}` ({vuln.get('product')}): "
                    f"CVSS {vuln.get('cvss', '?')} · KEV {vuln.get('kev', '?')}"
                )
            for warning in report["osint"].get("warnings") or []:
                st.caption(f"⚠ {warning}")

    with right:
        with st.container(border=True):
            st.markdown('<div class="ir-card-title">Why this confidence</div>', unsafe_allow_html=True)
            for reason in report["reasons"]:
                st.markdown(f"- {reason}")
            if report["memory_signals"]:
                st.markdown(
                    "".join(
                        chip(f"{s['label']} {s['impact']}", None) for s in report["memory_signals"]
                    ),
                    unsafe_allow_html=True,
                )

        st.markdown('<div class="ir-card-title" style="margin-top:10px">Recalled from memory</div>', unsafe_allow_html=True)
        if report["similar"]:
            for inc in report["similar"]:
                st.markdown(incident_card(inc), unsafe_allow_html=True)
        else:
            empty_state(
                "No close historical match",
                "Memory is OFF, empty, or this pattern is genuinely new. The agent falls back to the generic playbook.",
            )

    st.markdown('<div class="ir-card-title" style="margin-top:14px">Recommended actions</div>', unsafe_allow_html=True)
    for index, (action, why) in enumerate(report["actions"], start=1):
        st.markdown(
            action_row(index, ACTION_TEXT.get(action, action), why),
            unsafe_allow_html=True,
        )

    with st.expander("Agent trace · seven stages, every intermediate result inspectable"):
        trace_df = pd.DataFrame(report["trace"])
        st.dataframe(trace_df, width="stretch", hide_index=True)
        if report.get("recall"):
            st.markdown("**Hindsight recall metadata**")
            st.json(report["recall"])
        st.caption(
            "The trace is generated from deterministic stages. The LLM only writes the "
            "summary; it never chooses the risk score or the actions."
        )

    d1, d2 = st.columns(2)
    with d1:
        st.download_button(
            "Download incident report · Markdown",
            data=report_markdown(report).encode("utf-8"),
            file_name=f"intelliresponse-{p.get('category', 'alert')}-{date.today().isoformat()}.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with d2:
        st.download_button(
            "Download full evidence · JSON",
            data=report_json(report).encode("utf-8"),
            file_name=f"intelliresponse-{p.get('category', 'alert')}-{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=True,
        )

    st.divider()
    st.markdown('<div class="ir-card-title">Analyst verdict · this is the learning signal</div>', unsafe_allow_html=True)
    default_actions = [a for a, _ in report["actions"] if a in ACTION_TEXT][:3]
    default_verdict = 1 if (report["benign"] or report["risk"] == "LOW") else 0
    with st.form("verdict_form"):
        c1, c2 = st.columns([1, 1.5])
        with c1:
            verdict = st.radio(
                "Verdict",
                options=list(VERDICT_LABELS),
                index=default_verdict,
                format_func=lambda v: VERDICT_LABELS[v],
                horizontal=True,
            )
        with c2:
            taken = st.multiselect(
                "Actions you actually took",
                options=list(ACTION_TEXT),
                default=default_actions,
                format_func=lambda a: ACTION_TEXT[a],
            )
        note = st.text_input(
            "Root cause / note",
            placeholder="e.g. scheduled vulnerability scan by the security team",
        )
        submitted = st.form_submit_button("Save verdict & re-triage", type="primary")
    st.caption(
        "Two independent FALSE_POSITIVE verdicts for the same source are required before the "
        "agent auto-downgrades it. One verdict changes recommendations; two change the risk call."
    )
    if submitted:
        inc_id = record_outcome(mem, report, verdict, taken, note)
        with st.spinner("Memory updated. Re-running the same alert…"):
            new_report = investigate(
                sget("rep_raw", ""),
                mem,
                use_memory=bool(sget("memory_enabled", True)),
                live=bool(sget("live_osint", False)),
            )
        S["previous_rep"] = report
        S["rep"] = new_report
        S["last_saved"] = inc_id
        S["flash"] = (
            f"Saved **{inc_id}**. The agent re-ran the same alert; compare the new call below."
        )
        st.rerun()

    if S.get("previous_rep") and S.get("last_saved"):
        prev = S["previous_rep"]
        cur = report
        st.markdown(
            callout(
                f"Learning loop closed · {S['last_saved']}",
                f"Before: {prev['risk']} at {int(prev['confidence'] * 100)}% → "
                f"After: {cur['risk']} at {int(cur['confidence'] * 100)}%. "
                "The change is already persisted and will survive a restart.",
                "ok",
            ),
            unsafe_allow_html=True,
        )


# =============================================================================
# Triage page
# =============================================================================

if S["nav"] == "Triage":
    status = mem.status()
    hero(
        "SOC triage · memory-powered",
        "Every analyst verdict makes the next alert faster.",
        "IntelliResponse turns your team's past false positives, confirmed attacks and "
        "response actions into a durable memory layer. Same alert in, a different — "
        "evidence-backed — call out.",
        [
            risk_badge("LOW" if status["connected"] else "MEDIUM"),
            badge(f"Memory {'ON' if S.get('memory_enabled') else 'OFF'}", "ok" if S.get("memory_enabled") else "warn"),
            badge("Defensive use only", "info"),
        ],
    )

    if S.get("flash"):
        st.success(spop("flash"))

    with st.container(border=True):
        st.markdown('<div class="ir-card-title">Step 1 · Ingest an alert</div>', unsafe_allow_html=True)
        c1, c2 = st.columns([2, 1])
        with c1:
            st.selectbox(
                "Sample alert",
                SAMPLE_KEYS + ["Custom (paste logs)"],
                key="pick_alert",
                on_change=_sample_changed,
            )
        with c2:
            st.caption(
                f"Memory: **{'ON' if S.get('memory_enabled') else 'OFF'}** · "
                f"OSINT: **{'LIVE' if S.get('live_osint') else 'CACHED'}**"
            )
            st.button("Load sample text", on_click=_load_sample, use_container_width=True)
        st.text_area(
            "Raw alert / logs",
            key="raw_alert",
            height=175,
            placeholder="Paste SSH, firewall, DNS or SIEM logs here…",
        )
        b1, b2, _ = st.columns([1, 1, 2])
        with b1:
            run_clicked = st.button("Investigate", type="primary", use_container_width=True)
        with b2:
            st.caption("The parser extracts IOCs before any model call.")
        if run_clicked:
            run_investigation(sget("raw_alert", ""))

    if sget("auto_run"):
        S["auto_run"] = False
        run_investigation(sget("raw_alert", ""))

    report = sget("rep")
    if report:
        render_report(report)
    else:
        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
        section("Start here", "Three alerts, three very different memories")
        empty_state(
            "No investigation yet",
            "Choose a sample above and press Investigate. The first run takes under a second "
            "with cached OSINT and no LLM key.",
        )
        st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
        cols = st.columns(3, gap="large")
        samples = [
            (B_KEY, "Already learned", "The scanner that cries wolf every month. Memory should downgrade it to LOW and recommend allowlisting."),
            (A_KEY, "Genuinely new", "A new brute-force source in a known-bad /24. Memory should raise it to HIGH and cite the range history."),
            (C_KEY, "The dangerous repeat", "DNS beaconing to a known C2 domain. Memory should add reimage + persistence checks learned from INC-018."),
        ]
        for col, (key, title, body) in zip(cols, samples, strict=False):
            with col:
                st.markdown(
                    f'<div class="ir-card"><div class="ir-kicker">{esc(title)}</div>'
                    f'<div style="font-weight:750;font-size:15px;line-height:1.35;margin-bottom:6px">'
                    f'{esc(key)}</div>'
                    f'<div style="color:var(--ir-muted);font-size:12.5px;line-height:1.5">{esc(body)}</div></div>',
                    unsafe_allow_html=True,
                )
                st.button(
                    "Run this alert",
                    key=f"run_{key}",
                    on_click=_pick_sample,
                    args=(key,),
                    use_container_width=True,
                )


# =============================================================================
# Learning page
# =============================================================================

elif S["nav"] == "Learning":
    hero(
        "Learning loop",
        "The agent gets measurably better, not just chattier.",
        "This page is the audit trail of memory: what the agent believes, how often it is right, "
        "which sources are benign, and which actions actually worked.",
        [badge("Hindsight recall + reflect", "ok"), badge("Deterministic fallback", "muted")],
    )
    stats = learning_stats(mem)
    if not stats["total"]:
        empty_state("Memory is empty", "Load the demo history from the sidebar to see the learning curve.")
        st.button("Load 20 demo incidents", on_click=_demo_step, args=(2,))
    else:
        right, total = stats["accuracy"]
        cols = st.columns(4)
        with cols[0]:
            st.markdown(kpi("Incidents", str(stats["total"]), "analyst-reviewed history", "info"), unsafe_allow_html=True)
        with cols[1]:
            st.markdown(kpi("Verdicts", str(stats["verdicts"]), "feedback captured in this workspace", "neutral"), unsafe_allow_html=True)
        with cols[2]:
            st.markdown(
                kpi(
                    "Prediction accuracy",
                    f"{right}/{total}" if total else "—",
                    "agent calls that matched the analyst" if total else "save a verdict to start",
                    "ok" if total and right / total >= 0.7 else "warn",
                ),
                unsafe_allow_html=True,
            )
        with cols[3]:
            st.markdown(
                kpi(
                    "Estimated time saved",
                    f"{stats['saved_minutes_estimate'] / 60:.1f} h",
                    "18 min per repeated false-positive investigation",
                    "ok",
                ),
                unsafe_allow_html=True,
            )

        left, right_col = st.columns([1.1, 1], gap="large")
        with left:
            with st.container(border=True):
                st.markdown('<div class="ir-card-title">True-positive rate by category</div>', unsafe_allow_html=True)
                cat_df = pd.DataFrame(
                    [
                        {"Category": row["label"], "TP rate": row["rate"], "Incidents": row["n"]}
                        for row in stats["category_rates"].values()
                    ]
                )
                st.bar_chart(cat_df.set_index("Category")["TP rate"], color="#3ce0c0")
                st.caption("Smoothed with a Beta(1,1) prior so one verdict cannot dominate.")
        with right_col:
            with st.container(border=True):
                st.markdown('<div class="ir-card-title">Memory timeline</div>', unsafe_allow_html=True)
                timeline = pd.DataFrame(stats["timeline"])
                if not timeline.empty:
                    timeline = timeline.set_index("month")[["true_positive", "false_positive"]]
                    timeline.columns = ["True positive", "False positive"]
                    st.line_chart(timeline, color=["#ff6b8a", "#3ce0c0"])
                st.caption("The 20-incident demo history spans Apr–Oct 2026.")

        left2, right2 = st.columns([1, 1], gap="large")
        with left2:
            with st.container(border=True):
                st.markdown('<div class="ir-card-title">Confidence calibration</div>', unsafe_allow_html=True)
                cal_rows = [
                    {
                        "Predicted confidence": bucket,
                        "Reviewed": row["n"],
                        "Actually malicious": row["tp"],
                        "Observed precision": f"{row['tp'] / row['n']:.0%}" if row["n"] else "—",
                    }
                    for bucket, row in stats["calibration"].items()
                ]
                st.dataframe(pd.DataFrame(cal_rows), width="stretch", hide_index=True)
                st.caption("Built from live alerts only, where the agent stored its own prediction.")
        with right2:
            with st.container(border=True):
                st.markdown('<div class="ir-card-title">Sources learned as benign</div>', unsafe_allow_html=True)
                if stats["benign_details"]:
                    for detail in stats["benign_details"]:
                        cats = ", ".join(CATEGORY_LABELS.get(c, c) for c in detail["categories"])
                        st.markdown(
                            f"**`{detail['source']}`** — false positive in "
                            f"**{detail['count']}** incidents ({cats}); last seen {detail['last_seen']}."
                        )
                        st.caption(f"Actions: {', '.join(ACTION_TEXT.get(a, a) for a in detail['actions']) or 'none'}")
                else:
                    st.caption("Nothing learned yet. Two independent false-positive verdicts are required.")
                st.markdown(
                    callout(
                        "Why this matters",
                        "A scanner that trips the same alert every month is pure noise. "
                        "The agent remembers it and stops recommending a block.",
                        "ok",
                    ),
                    unsafe_allow_html=True,
                )

        with st.container(border=True):
            st.markdown('<div class="ir-card-title">Action effectiveness</div>', unsafe_allow_html=True)
            action_df = pd.DataFrame(stats["actions"])
            if not action_df.empty:
                action_df = action_df.rename(
                    columns={
                        "label": "Action",
                        "n": "Used",
                        "tp": "Confirmed malicious",
                        "fp": "False positive",
                        "precision": "Precision",
                    }
                )[["Action", "Used", "Confirmed malicious", "False positive", "Precision"]]
                st.dataframe(action_df, width="stretch", hide_index=True)
            else:
                st.caption("No actions recorded yet.")

        st.markdown("<div style='height:6px'></div>", unsafe_allow_html=True)
        c1, c2 = st.columns([1, 2])
        with c1:
            if st.button("Reflect on memory", type="primary", use_container_width=True):
                S["reflection"] = reflect_view(mem)
        with c2:
            st.caption(
                "Reflect uses Hindsight when connected; otherwise a deterministic synthesis of "
                "the same memory. It never invents a source."
            )
        reflection = sget("reflection")
        if reflection:
            with st.container(border=True):
                st.markdown(f"*Source: {reflection['source']}*")
                if reflection.get("error"):
                    st.caption(f"Fallback reason: {reflection['error']}")
                st.markdown(reflection["text"])


# =============================================================================
# History page
# =============================================================================

elif S["nav"] == "History":
    hero(
        "Incident ledger",
        "The structured mirror behind every recall.",
        "Hindsight is the semantic memory. This ledger keeps the canonical incident records "
        "replayable and inspectable, even when the network is down.",
        [badge("Durable local mirror", "ok"), badge("Hindsight-compatible records", "info")],
    )
    incidents = mem.incidents()
    if not incidents:
        empty_state("No incidents in memory", "Load the demo history from the sidebar, or save a live verdict.")
        st.button("Load 20 demo incidents", on_click=_demo_step, args=(2,))
    else:
        f1, f2, f3 = st.columns([1, 1, 1.3])
        categories = ["All"] + sorted({i["category"] for i in incidents})
        verdicts = ["All", "TRUE_POSITIVE", "FALSE_POSITIVE"]
        with f1:
            category_filter = st.selectbox("Category", categories)
        with f2:
            verdict_filter = st.selectbox("Verdict", verdicts, format_func=lambda v: "All" if v == "All" else VERDICT_LABELS.get(v, v))
        with f3:
            search = st.text_input("Search source, cause or summary", placeholder="198.51.100.7, scanner, C2…")

        filtered = incidents
        if category_filter != "All":
            filtered = [i for i in filtered if i["category"] == category_filter]
        if verdict_filter != "All":
            filtered = [i for i in filtered if i["verdict"] == verdict_filter]
        if search:
            needle = search.lower()
            filtered = [
                i
                for i in filtered
                if needle in " ".join(str(i.get(k, "")) for k in ("src", "cause", "summary", "actions", "id")).lower()
            ]

        df = pd.DataFrame(filtered)
        if not df.empty:
            df = df.rename(
                columns={
                    "id": "Incident",
                    "date": "Date",
                    "category": "Category",
                    "src": "Source",
                    "service": "Service",
                    "summary": "Summary",
                    "cause": "Root cause",
                    "verdict": "Verdict",
                    "actions": "Actions",
                    "pred": "Agent prediction",
                }
            )
        st.caption(f"{len(filtered)} of {len(incidents)} incidents shown")
        st.dataframe(df, width="stretch", hide_index=True)
        st.download_button(
            "Download ledger · CSV",
            data=df.apply(lambda col: col.map(csv_safe)).to_csv(index=False).encode("utf-8"),
            file_name="intelliresponse-incident-ledger.csv",
            mime="text/csv",
        )


# =============================================================================
# Memory inspector
# =============================================================================

elif S["nav"] == "Memory":
    hero(
        "Memory inspector",
        "Show the judges the memory, not just the answer.",
        "Every retain, recall, reflect and verdict is logged here. Connect a Hindsight bank "
        "to make the same operations semantic and persistent across sessions.",
        [badge("retain", "ok"), badge("recall", "ok"), badge("reflect", "ok")],
    )
    status = mem.status()
    cols = st.columns(4)
    with cols[0]:
        st.markdown(
            kpi("Backend", "Hindsight" if status["connected"] else "Local", status["detail"][:110], "ok" if status["connected"] else "warn"),
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(kpi("Memories", str(status["local_memories"]), f"{status['synced_memories']} synced to Hindsight", "info"), unsafe_allow_html=True)
    with cols[2]:
        st.markdown(kpi("Bank", status["bank"], status.get("api_version") or "durable mirror", "neutral"), unsafe_allow_html=True)
    with cols[3]:
        st.markdown(kpi("Events", str(status["events"]), "last 300 operations retained", "neutral"), unsafe_allow_html=True)

    c1, c2 = st.columns([1, 1])
    with c1:
        if st.button("Test Hindsight connection", type="primary", use_container_width=True):
            S["connection_result"] = mem.test_connection()
        result = sget("connection_result")
        if result:
            if result.get("ok"):
                st.success(
                    f"Connected to bank `{result['bank']}` · API {result['api_version']} · "
                    f"{result['latency_ms']} ms"
                )
            else:
                st.error(result.get("detail") or "Connection failed")
                if result.get("hint"):
                    st.caption(result["hint"])
    with c2:
        st.download_button(
            "Export memory · JSON",
            data=json.dumps(mem.export(), indent=2, default=str).encode("utf-8"),
            file_name=f"intelliresponse-memory-{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=True,
        )

    if not status["connected"]:
        with st.container(border=True):
            st.markdown('<div class="ir-card-title">Connect Hindsight in 60 seconds</div>', unsafe_allow_html=True)
            st.code(
                "HINDSIGHT_URL=https://api.hindsight.vectorize.io\n"
                "HINDSIGHT_API_KEY=your-key\n"
                "HINDSIGHT_BANK=intelliresponse-demo\n"
                "# or a local server: HINDSIGHT_URL=http://localhost:8888\n"
                "# optional: GROQ_API_KEY=... for LLM summaries",
                language="bash",
            )
            st.caption(
                "The demo is fully functional without keys: the durable mirror keeps memory "
                "and the deterministic engine keeps triage working. Hindsight adds semantic "
                "recall, reflect and cross-session persistence."
            )
            st.markdown(
                "[Create a Hindsight Cloud bank](https://ui.hindsight.vectorize.io/) · "
                "promo code `MEMHACK99` for credits."
            )

    with st.expander("Bank mission and directives (what Hindsight is told to prioritize)"):
        st.markdown(f"**Mission:** {status['mission']}")
        for directive in status["directives"]:
            st.markdown(f"- **{directive}**")

    st.markdown('<div class="ir-card-title" style="margin-top:14px">Operation log</div>', unsafe_allow_html=True)
    if mem.events:
        events = pd.DataFrame(mem.events[-60:])
        st.dataframe(events[["ts", "kind", "detail", "backend"]], width="stretch", hide_index=True)
    else:
        st.caption("No operations yet.")

    st.markdown('<div class="ir-card-title" style="margin-top:14px">Raw retained memories</div>', unsafe_allow_html=True)
    kind_filter = st.selectbox("Filter by kind", ["All"] + sorted({m.get("kind", "unknown") for m in mem.local}))
    rows = [m for m in mem.local if kind_filter == "All" or m.get("kind") == kind_filter]
    if rows:
        raw_df = pd.DataFrame(
            [
                {
                    "Kind": m.get("kind"),
                    "Created": m.get("created_at"),
                    "Timestamp": m.get("ts"),
                    "Synced": "✓" if m.get("synced") else "—",
                    "Memory": m.get("text"),
                }
                for m in rows[-80:]
            ]
        )
        st.dataframe(raw_df, width="stretch", hide_index=True)
    else:
        st.caption("No memories of this kind.")

    st.divider()
    st.markdown('<div class="ir-card-title">Danger zone</div>', unsafe_allow_html=True)
    st.caption("Reset clears the local mirror and, when connected, attempts to clear the Hindsight bank. Use it before a live demo.")
    confirm = st.checkbox("I understand this wipes the demo memory")
    st.button("Reset memory", on_click=_request_reset, disabled=not confirm)


# =============================================================================
# Demo / Guide page
# =============================================================================

elif S["nav"] == "Demo":
    hero(
        "The 60-second demo",
        "Problem → agent → memory changes the call.",
        "Run the four beats below in order. The only difference between beats is what the "
        "agent remembers; the alert parser and risk engine are identical.",
        [badge("Built for Hack with Hyderabad 3.0", "ok"), badge("Hindsight retain / recall / reflect", "info")],
    )

    section("Run it live", "Four buttons, one story")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Beat 1</div>'
            '<div style="font-weight:750">Stateless baseline</div>'
            '<div style="color:var(--ir-muted);font-size:12px;margin-top:5px">Memory OFF, 0 incidents. '
            'The scanner alert looks MEDIUM and the playbook says consider blocking.</div></div>',
            unsafe_allow_html=True,
        )
        st.button("Run beat 1", on_click=_demo_step, args=(1,), use_container_width=True)
    with c2:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Beat 2</div>'
            '<div style="font-weight:750">The memory moment</div>'
            '<div style="color:var(--ir-muted);font-size:12px;margin-top:5px">Load 20 incidents, same alert. '
            'Now it is LOW, 12%, false positive 4/4, allowlist the scanner.</div></div>',
            unsafe_allow_html=True,
        )
        st.button("Run beat 2", on_click=_demo_step, args=(2,), use_container_width=True)
    with c3:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Beat 3</div>'
            '<div style="font-weight:750">New attacker</div>'
            '<div style="color:var(--ir-muted);font-size:12px;margin-top:5px">A new IP in a known-bad /24. '
            'Memory raises the risk and ranks actions from confirmed incidents.</div></div>',
            unsafe_allow_html=True,
        )
        st.button("Run beat 3", on_click=_demo_step, args=(3,), use_container_width=True)
    with c4:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Beat 4</div>'
            '<div style="font-weight:750">Dangerous repeat</div>'
            '<div style="color:var(--ir-muted);font-size:12px;margin-top:5px">DNS beaconing to a known C2. '
            'Memory adds reimage + persistence checks learned from INC-018.</div></div>',
            unsafe_allow_html=True,
        )
        st.button("Run beat 4", on_click=_demo_step, args=(4,), use_container_width=True)

    st.markdown("<div style='height:14px'></div>", unsafe_allow_html=True)
    section("How it works", "One orchestrator, seven deterministic stages")
    flow(
        [
            ("01", "Parse", "Regex + validation extracts IPs, domains, hashes, service, volume."),
            ("02", "Recall", "Hindsight semantic recall + structural ranking over the local ledger."),
            ("03", "Enrich", "CISA KEV / OTX when available; cached sample otherwise."),
            ("04", "Correlate", "MITRE mapping, OSINT and learned verdicts become one score."),
            ("05", "Recommend", "Actions are ranked by what worked in similar incidents."),
            ("06", "Reason", "Groq writes the summary; deterministic template is the fallback."),
            ("07", "Report", "IOCs, evidence, memory impact, trace, export, verdict capture."),
        ]
    )

    with st.expander("Where Hindsight is used (the 25% judging criterion)"):
        mapping = pd.DataFrame(
            [
                ["retain", "Every seeded incident, live alert verdict, root cause and action set", "Builds the memory bank; survives restarts"],
                ["recall", "New alert query: category + service + source IP + domain + verdict context", "Returns the incidents behind the risk score and action ranking"],
                ["reflect", "“Which sources cause false positives and what actions work?”", "Produces the learning page narrative and patterns"],
                ["bank mission", "Defensive SOC memory; evidence before benign; explain the call", "Steers extraction and reflection toward SOC-relevant facts"],
                ["directives", "Defensive use only; two false positives before auto-downgrade", "Hard guardrails on reflect"],
            ],
            columns=["Hindsight primitive", "What IntelliResponse stores / asks", "What changes in the product"],
        )
        st.dataframe(mapping, width="stretch", hide_index=True)
        st.caption(
            "Fallback: a durable local mirror keeps the structured ledger replayable when Hindsight "
            "is unreachable. The UI labels which backend is active; it never pretends."
        )

    section("Why this is not another SOC chatbot", "The wedge is false-positive memory")
    cols = st.columns(3, gap="large")
    with cols[0]:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Wedge 1</div>'
            '<div style="font-weight:750;font-size:16px">The verdict is the product</div>'
            '<div style="color:var(--ir-muted);font-size:13px;line-height:1.55;margin-top:6px">'
            'Most audit tools log what happened. IntelliResponse turns the analyst’s verdict into '
            'the next risk score and the next action list. Memory is the decision layer.</div></div>',
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Wedge 2</div>'
            '<div style="font-weight:750;font-size:16px">Calibrated, not confident</div>'
            '<div style="color:var(--ir-muted);font-size:13px;line-height:1.55;margin-top:6px">'
            'The agent shows the stateless baseline beside the memory-informed call, then tracks '
            'whether its high-confidence calls actually match the analyst.</div></div>',
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            '<div class="ir-card"><div class="ir-kicker">Wedge 3</div>'
            '<div style="font-weight:750;font-size:16px">Built for a real buyer</div>'
            '<div style="color:var(--ir-muted);font-size:13px;line-height:1.55;margin-top:6px">'
            'A 3–15 person SOC or MSSP drowns in repeat false positives. The buyer is the SOC lead '
            'who wants fewer wasted investigations and consistent first response.</div></div>',
            unsafe_allow_html=True,
        )

    with st.expander("Business case, adoption path and honest limitations"):
        st.markdown(
            """
**Customer.** Small and mid-size SOCs, MSSPs, and platform teams without a 24/7 tier-1 analyst.

**Pain.** The same scanner, pen-test range or monitoring agent trips alerts every week. Analysts re-investigate from scratch, and the knowledge leaves when they do.

**Value.** Fewer wasted tier-1 investigations, faster first response, consistent decisions, and institutional memory that survives turnover. The demo estimates 18 minutes saved per repeated false-positive investigation; that is an illustrative planning number, not a measured outcome.

**Pricing.** Per-analyst seat or per-monitored-asset subscription. An MSSP edition would isolate one Hindsight bank per customer.

**Adoption path.** Paste logs → SIEM webhook (`/v1/triage`) → ticket integration for verdict capture → live OSINT → per-customer banks. The `api.py` service is included for the webhook path.

**Limitations.** The demo history is synthetic. The parser handles the three scoped categories (brute force, port scan, DNS beaconing), not every SIEM schema. The local mirror is the canonical structured ledger; Hindsight is the semantic memory. The agent recommends defensive actions and never executes them. Live OSINT depends on third-party availability; cached data is clearly labelled.
            """
        )

    with st.expander("Judge Q&A · the questions that decide the score"):
        st.markdown(
            """
**“Is this just a chatbot?”** No. The parser, ranking, risk score and actions are deterministic. The LLM writes the summary only. The memory changes the decision, not just the prose.

**“Is Hindsight central?”** Yes. Without recall there is no similar-incident evidence, no auto-downgrade, no history-ranked action list and no learning page. The sidebar shows the backend; the trace shows the recall metadata; the memory inspector shows every retain/recall/reflect.

**“What happens if Hindsight is down?”** The durable mirror keeps triage working and the UI says `FALLBACK`. The demo never breaks silently; it degrades honestly.

**“Why not use a vector DB?”** Recall is not just semantic similarity. The product depends on temporal history, analyst verdicts, entity links (source IP / /24 / domain) and reflect over patterns. That is the memory layer, not a document search.

**“What is the one-line pitch?”** The false-positive memory layer for SOC triage: every analyst verdict makes the next alert faster.
            """
        )

    st.markdown(
        callout(
            "Safety and ethics",
            "All IPs are RFC 5737 documentation ranges and all domains use the reserved .example "
            "TLD. No real attacker is named. OSINT samples are illustrative when offline. "
            "IntelliResponse only recommends defensive actions; it never blocks, isolates or "
            "executes anything.",
            "info",
        ),
        unsafe_allow_html=True,
    )

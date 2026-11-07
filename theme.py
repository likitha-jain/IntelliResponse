"""Cybersecurity-focused UI theme and modern visual components for IntelliResponse."""
from __future__ import annotations

import html
from typing import Any
import streamlit as st


def esc(value: Any) -> str:
    """Safely escape HTML entities."""
    if value is None:
        return ""
    return html.escape(str(value))


def inject_css() -> None:
    """Inject polished, modern dark-mode styles for SOC operations."""
    st.markdown(
        """
        <style>
        :root {
            --ir-bg: #0b0f17;
            --ir-card-bg: #111827;
            --ir-card-border: #1f293d;
            --ir-accent: #00e5a3;
            --ir-accent-dim: rgba(0, 229, 163, 0.12);
            --ir-danger: #ef4444;
            --ir-danger-dim: rgba(239, 68, 68, 0.14);
            --ir-warn: #f59e0b;
            --ir-warn-dim: rgba(245, 158, 11, 0.14);
            --ir-info: #38bdf8;
            --ir-info-dim: rgba(56, 189, 248, 0.14);
            --ir-text: #f1f5f9;
            --ir-muted: #94a3b8;
        }

        /* Branding in Sidebar */
        .ir-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 4px 12px 4px;
        }
        .ir-logo {
            font-size: 28px;
            background: linear-gradient(135deg, rgba(0,229,163,0.2), rgba(56,189,248,0.2));
            padding: 8px;
            border-radius: 10px;
            border: 1px solid var(--ir-card-border);
        }
        .ir-brand-name {
            font-size: 19px;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: var(--ir-text);
        }
        .ir-brand-sub {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--ir-accent);
            font-weight: 600;
        }

        /* General Card Containers */
        .ir-card {
            background: var(--ir-card-bg);
            border: 1px solid var(--ir-card-border);
            border-radius: 12px;
            padding: 18px 20px;
            margin-bottom: 14px;
            transition: border-color 0.15s ease;
        }
        .ir-card:hover {
            border-color: #2e3d5b;
        }
        .ir-kicker {
            font-size: 10.5px;
            text-transform: uppercase;
            letter-spacing: 0.09em;
            font-weight: 750;
            color: var(--ir-accent);
            margin-bottom: 6px;
        }
        .ir-card-title {
            font-size: 14.5px;
            font-weight: 750;
            color: var(--ir-text);
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Badges & Chips */
        .ir-badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 9px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.02em;
        }
        .ir-badge-ok {
            background: var(--ir-accent-dim);
            color: var(--ir-accent);
            border: 1px solid rgba(0, 229, 163, 0.3);
        }
        .ir-badge-danger {
            background: var(--ir-danger-dim);
            color: var(--ir-danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        .ir-badge-warn {
            background: var(--ir-warn-dim);
            color: var(--ir-warn);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        .ir-badge-info {
            background: var(--ir-info-dim);
            color: var(--ir-info);
            border: 1px solid rgba(56, 189, 248, 0.3);
        }
        .ir-badge-muted {
            background: rgba(148, 163, 184, 0.1);
            color: var(--ir-muted);
            border: 1px solid rgba(148, 163, 184, 0.2);
        }

        .ir-chip {
            display: inline-block;
            background: #182234;
            color: #e2e8f0;
            border: 1px solid #293850;
            border-radius: 6px;
            padding: 3px 8px;
            font-size: 11.5px;
            margin: 0 4px 6px 0;
        }
        .ir-chip code {
            color: var(--ir-accent);
            font-weight: bold;
        }

        /* KPI Metric Block */
        .ir-kpi {
            padding: 14px 16px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        .ir-kpi-label {
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 700;
            letter-spacing: 0.06em;
            color: var(--ir-muted);
            margin-bottom: 4px;
        }
        .ir-kpi-value {
            font-size: 26px;
            font-weight: 850;
            color: var(--ir-text);
            line-height: 1.15;
        }
        .ir-kpi-caption {
            font-size: 11px;
            color: var(--ir-muted);
            margin-top: 5px;
            line-height: 1.3;
        }
        .ir-kpi-ok .ir-kpi-value { color: var(--ir-accent); }
        .ir-kpi-danger .ir-kpi-value { color: var(--ir-danger); }
        .ir-kpi-warn .ir-kpi-value { color: var(--ir-warn); }
        .ir-kpi-info .ir-kpi-value { color: var(--ir-info); }

        /* Impact Diff Box */
        .ir-impact-card {
            background: linear-gradient(145deg, #131c2e, #0e1625);
            border: 1px solid #24344f;
            border-radius: 12px;
            padding: 16px 20px;
            margin-bottom: 16px;
        }
        .ir-impact-grid {
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            gap: 16px;
            align-items: center;
            margin-top: 10px;
        }
        .ir-impact-side {
            background: rgba(10, 15, 25, 0.6);
            border: 1px solid #1f2b42;
            border-radius: 8px;
            padding: 12px 14px;
        }

        /* Action Rows */
        .ir-action-row {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 10px 14px;
            background: #141c2c;
            border: 1px solid #1e2a40;
            border-radius: 8px;
            margin-bottom: 8px;
        }
        .ir-action-num {
            background: var(--ir-accent-dim);
            color: var(--ir-accent);
            border: 1px solid rgba(0, 229, 163, 0.4);
            font-size: 11px;
            font-weight: 800;
            width: 22px;
            height: 22px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-shrink: 0;
            margin-top: 2px;
        }
        .ir-action-name {
            font-size: 13.5px;
            font-weight: 750;
            color: var(--ir-text);
        }
        .ir-action-why {
            font-size: 12px;
            color: var(--ir-muted);
            margin-top: 2px;
        }

        /* Recalled Incident Card */
        .ir-incident-card {
            background: #131b2a;
            border: 1px solid #212e45;
            border-radius: 8px;
            padding: 12px 14px;
            margin-bottom: 8px;
        }
        .ir-incident-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }
        .ir-incident-id {
            font-weight: 800;
            color: #38bdf8;
            font-size: 12.5px;
        }
        .ir-incident-cause {
            font-size: 12.5px;
            color: var(--ir-text);
            margin-bottom: 6px;
        }
        .ir-incident-matches {
            font-size: 11px;
            color: var(--ir-muted);
        }

        /* Callout Box */
        .ir-callout {
            border-radius: 10px;
            padding: 14px 18px;
            margin: 12px 0;
            border-left: 4px solid;
        }
        .ir-callout-ok {
            background: rgba(0, 229, 163, 0.08);
            border-color: var(--ir-accent);
        }
        .ir-callout-info {
            background: rgba(56, 189, 248, 0.08);
            border-color: var(--ir-info);
        }
        .ir-callout-warn {
            background: rgba(245, 158, 11, 0.08);
            border-color: var(--ir-warn);
        }
        .ir-callout-title {
            font-size: 13.5px;
            font-weight: 750;
            color: var(--ir-text);
            margin-bottom: 4px;
        }
        .ir-callout-body {
            font-size: 12.5px;
            color: var(--ir-muted);
            line-height: 1.45;
        }

        /* Flow Diagram */
        .ir-flow-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 8px;
            margin: 12px 0 16px 0;
        }
        .ir-flow-step {
            background: #141c2b;
            border: 1px solid #202b3d;
            border-radius: 8px;
            padding: 10px 12px;
            position: relative;
        }
        .ir-flow-num {
            font-size: 10px;
            font-weight: 800;
            color: var(--ir-accent);
            text-transform: uppercase;
        }
        .ir-flow-title {
            font-size: 12.5px;
            font-weight: 750;
            color: var(--ir-text);
            margin: 2px 0 4px 0;
        }
        .ir-flow-desc {
            font-size: 11px;
            color: var(--ir-muted);
            line-height: 1.35;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def badge(text: Any, tone: str = "info") -> str:
    """Render a styled inline badge."""
    valid_tones = {"ok", "danger", "warn", "info", "muted"}
    t = tone if tone in valid_tones else "info"
    return f'<span class="ir-badge ir-badge-{t}">{esc(text)}</span>'


def risk_badge(risk: str) -> str:
    """Render a colored badge for HIGH / MEDIUM / LOW risk."""
    tone_map = {"HIGH": "danger", "MEDIUM": "warn", "LOW": "ok"}
    tone = tone_map.get(risk.upper(), "info")
    return badge(risk, tone)


def chip(label: str, code: str | None = None) -> str:
    """Render a chip pill for MITRE techniques or extracted indicators."""
    prefix = f"<code>{esc(code)}</code> " if code else ""
    return f'<span class="ir-chip">{prefix}{esc(label)}</span>'


def kpi(label: str, value: str, caption: str, tone: str = "neutral") -> str:
    """Render a top-level KPI metric block."""
    return (
        f'<div class="ir-card ir-kpi ir-kpi-{esc(tone)}">'
        f'<div class="ir-kpi-label">{esc(label)}</div>'
        f'<div class="ir-kpi-value">{esc(value)}</div>'
        f'<div class="ir-kpi-caption">{esc(caption)}</div>'
        f"</div>"
    )


def hero(title: str, subtitle: str, desc: str, badges: list[str] | None = None) -> None:
    """Render the hero section at the top of a page."""
    badges_html = " ".join(badges) if badges else ""
    st.markdown(
        f'<div style="margin-bottom: 20px;">'
        f'<div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; flex-wrap: wrap;">'
        f'<div>'
        f'<h1 style="font-size: 26px; font-weight: 850; letter-spacing: -0.02em; margin-bottom: 4px;">{esc(title)}</h1>'
        f'<div style="font-size: 14.5px; font-weight: 600; color: var(--ir-accent); margin-bottom: 6px;">{esc(subtitle)}</div>'
        f'<div style="font-size: 13px; color: var(--ir-muted); max-width: 820px; line-height: 1.5;">{esc(desc)}</div>'
        f'</div>'
        f'<div style="display: flex; gap: 8px; align-items: center; margin-top: 4px;">{badges_html}</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )


def section(title: str, subtitle: str) -> None:
    """Render a section header."""
    st.markdown(
        f'<div style="margin: 18px 0 10px 0;">'
        f'<div class="ir-kicker">{esc(subtitle)}</div>'
        f'<div style="font-size: 17px; font-weight: 800; color: var(--ir-text);">{esc(title)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def callout(title: str, text: str, tone: str = "ok") -> str:
    """Render a callout banner."""
    return (
        f'<div class="ir-callout ir-callout-{esc(tone)}">'
        f'<div class="ir-callout-title">{esc(title)}</div>'
        f'<div class="ir-callout-body">{esc(text)}</div>'
        f'</div>'
    )


def empty_state(title: str, desc: str) -> None:
    """Render an empty state placeholder."""
    st.markdown(
        f'<div class="ir-card" style="text-align: center; padding: 30px 20px; border-style: dashed;">'
        f'<div style="font-size: 24px; margin-bottom: 6px;">🔍</div>'
        f'<div style="font-size: 14px; font-weight: 750; color: var(--ir-text); margin-bottom: 4px;">{esc(title)}</div>'
        f'<div style="font-size: 12.5px; color: var(--ir-muted); max-width: 460px; margin: 0 auto;">{esc(desc)}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


def impact(baseline: dict, current: dict, delta: dict, memory_used: bool) -> str:
    """Render the side-by-side Before/After Hindsight memory impact comparison."""
    if not memory_used:
        return ""

    base_risk = baseline["risk"]
    cur_risk = current["risk"]
    base_conf = int(baseline["confidence"] * 100)
    cur_conf = int(current["confidence"] * 100)

    delta_pct = f"{delta['confidence_delta']:+.0%}"
    direction_arrow = "↓" if delta["confidence_delta"] < 0 else "↑" if delta["confidence_delta"] > 0 else "→"

    return (
        f'<div class="ir-impact-card">'
        f'<div style="display:flex; justify-content:space-between; align-items:center;">'
        f'<div>'
        f'<span class="ir-kicker">Memory Impact Matrix</span>'
        f'<div style="font-weight:750; font-size:14px; color:var(--ir-text);">{esc(delta["impact"])}</div>'
        f'</div>'
        f'{badge("Hindsight Shift", "ok")}'
        f'</div>'
        f'<div class="ir-impact-grid">'
        f'<div class="ir-impact-side">'
        f'<div style="font-size:11px; text-transform:uppercase; color:var(--ir-muted); font-weight:700;">Stateless Baseline</div>'
        f'<div style="font-size:18px; font-weight:800; margin-top:2px;">{risk_badge(base_risk)} <span style="font-size:14px; font-weight:600; color:var(--ir-muted);">{base_conf}%</span></div>'
        f'<div style="font-size:11.5px; color:var(--ir-muted); margin-top:4px;">Generic rule playbook</div>'
        f'</div>'
        f'<div style="text-align:center; font-size:18px; font-weight:800; color:var(--ir-accent);">{direction_arrow} {delta_pct}</div>'
        f'<div class="ir-impact-side">'
        f'<div style="font-size:11px; text-transform:uppercase; color:var(--ir-accent); font-weight:700;">Hindsight Empowered</div>'
        f'<div style="font-size:18px; font-weight:800; margin-top:2px;">{risk_badge(cur_risk)} <span style="font-size:14px; font-weight:600; color:var(--ir-text);">{cur_conf}%</span></div>'
        f'<div style="font-size:11.5px; color:var(--ir-muted); margin-top:4px;">Calibrated by past analyst verdicts</div>'
        f'</div>'
        f'</div>'
        f'</div>'
    )


def incident_card(inc: dict) -> str:
    """Render a card for an incident recalled from memory."""
    reasons_str = ", ".join(inc.get("match_reasons", []))
    v_badge = badge(inc.get("verdict", "UNKNOWN"), "ok" if inc.get("verdict") == "FALSE_POSITIVE" else "danger")
    return (
        f'<div class="ir-incident-card">'
        f'<div class="ir-incident-header">'
        f'<div><span class="ir-incident-id">{esc(inc.get("id"))}</span> · <span style="font-size:11px; color:var(--ir-muted);">{esc(inc.get("date"))}</span></div>'
        f'{v_badge}'
        f'</div>'
        f'<div class="ir-incident-cause">{esc(inc.get("cause"))}</div>'
        f'<div class="ir-incident-matches">Matched on: <i>{esc(reasons_str)}</i></div>'
        f'</div>'
    )


def action_row(index: int, action_name: str, why: str) -> str:
    """Render an action recommendation row."""
    return (
        f'<div class="ir-action-row">'
        f'<div class="ir-action-num">{index}</div>'
        f'<div class="ir-action-body">'
        f'<div class="ir-action-name">{esc(action_name)}</div>'
        f'<div class="ir-action-why">{esc(why)}</div>'
        f'</div>'
        f'</div>'
    )


def flow(steps: list[tuple[str, str, str]]) -> None:
    """Render the 7-stage orchestrator flow visualization."""
    cards_html = ""
    for num, title, desc in steps:
        cards_html += (
            f'<div class="ir-flow-step">'
            f'<div class="ir-flow-num">{esc(num)}</div>'
            f'<div class="ir-flow-title">{esc(title)}</div>'
            f'<div class="ir-flow-desc">{esc(desc)}</div>'
            f'</div>'
        )
    st.markdown(f'<div class="ir-flow-grid">{cards_html}</div>', unsafe_allow_html=True)

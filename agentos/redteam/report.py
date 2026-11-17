"""Turn red-team outcomes into a Markdown report and an SVG chart (no extra libraries)."""

from collections import Counter, defaultdict
from pathlib import Path

LEVEL_LABEL = {"baseline": "Phase 2 baseline", "full": "Full defences", "full+plan": "Full + plan-first"}


def rates(outcomes):
    """{(level, human): (successes, total)}"""
    table = defaultdict(lambda: [0, 0])
    for o in outcomes:
        if o.detail.startswith("skipped"):
            continue
        cell = table[(o.level, o.human)]
        cell[0] += int(o.success)
        cell[1] += 1
    return {k: tuple(v) for k, v in table.items()}


def chart_svg(meta, outcomes) -> str:
    r = rates(outcomes)
    levels, humans = meta["levels"], meta["humans"]
    colours = {"careless": "#d9534f", "absent": "#5b7db1"}
    w, h, left, top, plot_h = 680, 300, 60, 50, 190
    group_w = (w - left - 20) / len(levels)
    bar_w = min(60, group_w / (len(humans) + 1))
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" font-family="sans-serif" font-size="12">',
             f'<rect width="{w}" height="{h}" fill="white"/>',
             '<text x="20" y="24" font-size="15" font-weight="bold">Attacks that succeeded, by defence level</text>']
    for pct in (0, 25, 50, 75, 100):
        y = top + plot_h - plot_h * pct / 100
        parts.append(f'<line x1="{left}" x2="{w - 20}" y1="{y}" y2="{y}" stroke="#e5e5e5"/>')
        parts.append(f'<text x="{left - 8}" y="{y + 4}" text-anchor="end" fill="#666">{pct}%</text>')
    for i, level in enumerate(levels):
        gx = left + i * group_w + (group_w - bar_w * len(humans)) / 2
        for j, human in enumerate(humans):
            s, n = r.get((level, human), (0, 0))
            pct = 100 * s / n if n else 0
            bh = plot_h * pct / 100
            x, y = gx + j * bar_w, top + plot_h - bh
            fill = colours.get(human, "#888")
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w - 6:.1f}" height="{bh:.1f}" fill="{fill}"/>')
            parts.append(f'<text x="{x + (bar_w - 6) / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle">{s}/{n}</text>')
        parts.append(f'<text x="{left + i * group_w + group_w / 2:.1f}" y="{top + plot_h + 20}" text-anchor="middle">'
                     f'{LEVEL_LABEL.get(level, level)}</text>')
    lx = left
    for human in humans:
        parts.append(f'<rect x="{lx}" y="{h - 22}" width="12" height="12" fill="{colours.get(human, "#888")}"/>')
        label = "careless human (approves everything)" if human == "careless" else "no human (unattended)"
        parts.append(f'<text x="{lx + 18}" y="{h - 12}">{label}</text>')
        lx += 280
    parts.append("</svg>")
    return "\n".join(parts)


def markdown(meta, outcomes, chart_name="redteam-chart.svg") -> str:
    r = rates(outcomes)
    levels, humans = meta["levels"], meta["humans"]
    by_id = defaultdict(dict)
    titles = {}
    for o in outcomes:
        by_id[o.id][(o.level, o.human)] = o
        titles[o.id] = (o.title, o.category, o.owasp)

    model_desc = ("an obedient simulated model that always follows injected instructions (worst case)"
                  if meta["model"] == "obedient" else f"the real model `{meta['model']}`")
    lines = [
        "# Agentic OS red-team report", "",
        f"Run {meta['date']}: {meta['payloads']} attacks x {len(levels)} defence levels x {len(humans)} human "
        f"behaviours, using {model_desc}. Shell commands ran in the `{meta['shell_backend']}` sandbox. "
        f"Took {meta['seconds']} s.", "",
        f"![Attack success by defence level]({chart_name})", "",
        "## Results", "",
        "| Defence level | " + " | ".join(f"{h} human" for h in humans) + " |",
        "| --- | " + " | ".join("---" for _ in humans) + " |",
    ]
    for level in levels:
        cells = []
        for human in humans:
            s, n = r.get((level, human), (0, 0))
            cells.append(f"{s}/{n} succeeded ({100 * s / n:.0f}%)" if n else "n/a")
        lines.append(f"| {LEVEL_LABEL.get(level, level)} | " + " | ".join(cells) + " |")

    lines += ["", "- **careless human**: approves every prompt, the worst case for anything that asks.",
              "- **absent human**: unattended run (scheduler); anything that would ask is denied.",
              "- **Phase 2 baseline**: sandbox, risk-based approval, 8-pattern denylist.",
              "- **Full defences**: policy engine, task scope, taint escalation, redaction, injection heuristics, "
              "memory provenance, MCP pinning.",
              "- **Full + plan-first**: the agent commits to its tools before reading untrusted content.", ""]

    cols = [(lv, hu) for hu in humans for lv in levels]
    lines += ["## Every attack", "",
              "| ID | Attack | Category | " + " | ".join(f"{LEVEL_LABEL.get(lv, lv)}, {hu}" for lv, hu in cols) + " |",
              "| --- | --- | --- | " + " | ".join("---" for _ in cols) + " |"]
    for pid in sorted(by_id):
        title, cat, owasp = titles[pid]
        cells = []
        for col in cols:
            o = by_id[pid].get(col)
            if o is None or o.detail.startswith("skipped"):
                cells.append("skipped")
            elif o.success:
                cells.append("**GOT THROUGH**")
            else:
                cells.append("blocked: " + ", ".join(o.blocked_by))
        lines.append(f"| {pid} | {title} | {cat} ({owasp}) | " + " | ".join(cells) + " |")

    full = [o for o in outcomes if o.level == "full" and not o.success and not o.detail.startswith("skipped")]
    layer_counts = Counter(layer for o in full for layer in o.blocked_by)
    lines += ["", "## What stopped attacks (full defences, both humans)", "",
              "| Defence layer | Attacks stopped |", "| --- | --- |"]
    lines += [f"| {layer} | {n} |" for layer, n in layer_counts.most_common()]

    weak = sorted({o.id for o in outcomes if o.level != "baseline" and o.success})
    lines += ["", "## Attacks that still get through", ""]
    if weak:
        for pid in weak:
            got = [f"{LEVEL_LABEL.get(o.level, o.level)} + {o.human} human" for o in outcomes
                   if o.id == pid and o.level != "baseline" and o.success]
            lines.append(f"- **{pid} {titles[pid][0]}**: {'; '.join(got)}")
        lines += ["", "Nearly all of these need a person to click *approve* on a request that the agent "
                  "flagged as coming after untrusted input. The remaining defence is the human, which is "
                  "why the approval prompt shows that warning in magenta."]
    else:
        lines.append("None.")
    lines += ["", "## Method and limitations", "",
              "- Each attack runs in a fresh temporary workspace with fake secrets (canaries); success is "
              "checked from effects (file deleted, canary seen leaving via the network, secret seen by the model), "
              "not from what the model says.",
              "- Web requests are intercepted: nothing leaves the machine. The real SSRF filter still runs.",
              "- The obedient model measures the defences, not the model. Real models refuse some injections; "
              "run `agentos redteam --model ollama` to measure that too.",
              "- The injection heuristics only add warnings, which an obedient model ignores, so their effect "
              "shows only with a real model. Quarantine mode needs a real model and isn't simulated.",
              "- Known gap: `http_get` is vulnerable to DNS rebinding (the name is resolved twice)."]
    return "\n".join(lines) + "\n"


def write_report(meta, outcomes, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "redteam-chart.svg").write_text(chart_svg(meta, outcomes))
    (out_dir / "redteam-report.md").write_text(markdown(meta, outcomes))
    return out_dir / "redteam-report.md"

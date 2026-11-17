"""
RiskSIEM: attack-impact data analysis (matplotlib)

Reads the project CSVs (assets, threats, exposure, treatments, control_map, ...)
and produces charts showing what happens to business risk when an attack occurs.

Usage:
    python risk_analysis.py                      # CSVs in ./data (or current folder), images to ./figures
    python risk_analysis.py --data path/to/csvs --out path/to/figures
    python risk_analysis.py --dark               # dark theme (for dark slides)

Needs: pandas, numpy, matplotlib
"""
import argparse
import math
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import BoundaryNorm, ListedColormap
from matplotlib.patches import Patch

# ------------------------------------------------------------------ settings
BANDS = ["Low", "Medium", "High", "Critical"]
BAND_COLORS = {"Low": "#E5E5E5", "Medium": "#FED7AA", "High": "#F97316", "Critical": "#9A3412"}
BAND_TEXT = {"Low": "#111111", "Medium": "#111111", "High": "#111111", "Critical": "#FFFFFF"}
ORANGE, BLACK, GREY = "#F97316", "#0B0B0C", "#71717A"
THREAT_SHORT = {"T1110": "Brute force", "T1046": "Port scan", "T1548": "Priv. escalation"}
THREAT_CODE = {"T1110": "BF", "T1046": "SCAN", "T1548": "PE"}

# The six simulated attacks used in the project (asset, threat, event count)
SCENARIOS = [
    ("S1", "A4", "T1548", 1),
    ("S2", "A1", "T1548", 1),
    ("S3", "A6", "T1110", 40),
    ("S4", "A2", "T1110", 12),
    ("S5", "A6", "T1046", 15),
    ("S6", "A5", "T1046", 15),
]
TREATMENT_EXPOSURE_DROP = 2  # assumption: a treatment lowers exposure by 2 (minimum 1)


# ------------------------------------------------------------ scoring method
def round_half_up(x):
    return math.floor(x + 0.5)


def clamp(x, lo=1, hi=5):
    return max(lo, min(hi, x))


def freq_bonus(threat_id, n):
    if threat_id == "T1110":      # failed attempts
        return 0.0 if n < 20 else 0.5 if n < 40 else 1.0
    if threat_id == "T1046":      # distinct ports
        return 0.0 if n < 25 else 0.5 if n < 50 else 1.0
    return 0.0                    # T1548


def band_of(risk):
    return "Critical" if risk >= 20 else "High" if risk >= 12 else "Medium" if risk >= 6 else "Low"


def score(asset, threat, exposure, n=0):
    """Return (likelihood, impact, risk) for one attack on one asset."""
    impact = clamp(round_half_up((asset["value"] + asset[threat["primary_dimension"]]) / 2))
    like = clamp(round_half_up((threat["base_likelihood"] + exposure) / 2 + freq_bonus(threat["threat_id"], n)))
    return like, impact, like * impact


# ------------------------------------------------------------------- loading
def load(data_dir):
    if not os.path.exists(os.path.join(data_dir, "assets.csv")):
        alt_dir = Path(__file__).resolve().parent.parent / "data"
        if (alt_dir / "assets.csv").exists():
            data_dir = str(alt_dir)
        elif os.path.exists(os.path.join(data_dir, "data", "assets.csv")):
            data_dir = os.path.join(data_dir, "data")
    rd = lambda f: pd.read_csv(os.path.join(data_dir, f))
    assets = rd("assets.csv").set_index("asset_id")
    threats = rd("threats.csv").set_index("threat_id", drop=False)
    exposure = rd("exposure.csv").set_index("asset_id")
    return assets, threats, exposure


def label(assets, aid):
    return f"{aid} {assets.loc[aid, 'hostname']}"


# --------------------------------------------------------------------- theme
def apply_theme(dark):
    fg, bg = ("#F4F4F5", BLACK) if dark else ("#111111", "#FFFFFF")
    plt.rcParams.update({
        "figure.facecolor": bg, "axes.facecolor": bg, "savefig.facecolor": bg,
        "text.color": fg, "axes.labelcolor": fg, "xtick.color": fg, "ytick.color": fg,
        "axes.edgecolor": GREY, "font.family": "DejaVu Sans", "font.size": 11,
        "axes.titlesize": 13, "axes.titleweight": "bold", "axes.titlelocation": "left",
        "axes.spines.top": False, "axes.spines.right": False,
    })
    return fg, bg


# -------------------------------------------------------------------- panels
def p_heatmap(ax, assets, threats, exposure):
    """Risk score if each attack type hits each asset (baseline, low volume)."""
    aids, tids = list(assets.index), list(threats.index)
    risk = np.zeros((len(aids), len(tids)), dtype=int)
    for i, a in enumerate(aids):
        for j, t in enumerate(tids):
            risk[i, j] = score(assets.loc[a], threats.loc[t], exposure.loc[a, t])[2]
    bidx = np.vectorize(lambda r: BANDS.index(band_of(r)))(risk)
    cmap = ListedColormap([BAND_COLORS[b] for b in BANDS])
    ax.imshow(bidx, cmap=cmap, norm=BoundaryNorm([-.5, .5, 1.5, 2.5, 3.5], cmap.N), aspect="auto")
    for i in range(len(aids)):
        for j in range(len(tids)):
            b = BANDS[bidx[i, j]]
            ax.text(j, i, str(risk[i, j]), ha="center", va="center", fontsize=15, fontweight="bold", color=BAND_TEXT[b])
    ax.set_xticks(range(len(tids)), [f"{THREAT_SHORT[t]}\n({t})" for t in tids])
    ax.set_yticks(range(len(aids)), [label(assets, a) for a in aids])
    ax.xaxis.tick_top()
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_xticks(np.arange(-.5, len(tids), 1), minor=True)
    ax.set_yticks(np.arange(-.5, len(aids), 1), minor=True)
    ax.grid(which="minor", color="white", linewidth=3)
    ax.tick_params(which="minor", length=0)
    ax.set_title("If an attack hits this asset, how bad is it?\n(risk score = likelihood × impact)", pad=34)
    ax.legend(handles=[Patch(color=BAND_COLORS[b], label=b) for b in BANDS], ncol=4, loc="upper center",
              bbox_to_anchor=(0.5, -0.03), frameon=False, fontsize=10)
    return risk


def p_volume(ax, assets, threats, exposure, tid="T1110", nmax=80):
    """Risk as the attack gets bigger (more failed logins / more scanned ports)."""
    ns = np.arange(1, nmax + 1)
    cols = ["#0B0B0C", "#F97316", "#71717A", "#C2410C", "#FB923C", "#A1A1AA"]
    styles = ["-", "-", "--", "-.", ":", "-"]
    for k, a in enumerate(assets.index):
        ys = [score(assets.loc[a], threats.loc[tid], exposure.loc[a, tid], n)[2] for n in ns]
        off = (k - 2.5) * 0.12  # tiny vertical offset so overlapping lines stay visible
        ax.plot(ns, np.array(ys) + off, drawstyle="steps-post", color=cols[k], ls=styles[k], lw=2.2, label=label(assets, a))
    for y, b in [(12, "High ≥ 12"), (20, "Critical ≥ 20")]:
        ax.axhline(y - 0.5, color=GREY, lw=0.8, ls=":")
        ax.text(nmax, y - 0.3, b, ha="right", va="bottom", fontsize=9, color=GREY)
    t1, t2 = (20, 40) if tid == "T1110" else (25, 50)
    for t in (t1, t2):
        if t <= nmax:
            ax.axvline(t, color=ORANGE, lw=1, ls="--", alpha=.7)
            ax.text(t + 0.6, 1.3, f"frequency\nbonus @ {t}", fontsize=8.5, color=ORANGE, va="bottom")
    ax.set_xlim(1, nmax)
    ax.set_ylim(0, 26)
    ax.set_xlabel("failed login attempts" if tid == "T1110" else "distinct ports scanned")
    ax.set_ylabel("risk score (1-25)")
    ax.set_title(f"Risk escalates with attack volume: {THREAT_SHORT[tid].lower()} ({tid})")
    ax.legend(fontsize=8.5, frameon=False, ncol=2, loc="lower right", bbox_to_anchor=(1, 0.08))


def p_bubble(ax, assets, threats, exposure):
    """All 18 asset/attack combinations in the likelihood-impact plane."""
    gx, gy = np.meshgrid(np.linspace(0.5, 5.5, 200), np.linspace(0.5, 5.5, 200))
    z = gx * gy
    cmap = ListedColormap([BAND_COLORS[b] for b in BANDS])
    ax.contourf(gx, gy, z, levels=[0, 5.5, 11.5, 19.5, 30], cmap=cmap, alpha=.35)
    pts = []
    for a in assets.index:
        for t in threats.index:
            l, i, r = score(assets.loc[a], threats.loc[t], exposure.loc[a, t])
            pts.append((a, t, l, i, r))
    seen = {}
    for a, t, l, i, r in pts:
        k = (l, i)
        n = seen.get(k, 0)
        seen[k] = n + 1
        dx = (n % 3 - 1) * 0.2 if n else 0
        dy = (n // 3) * 0.2 if n else 0
        b = band_of(r)
        ax.scatter(i + dx, l + dy, s=400, color=BAND_COLORS[b], edgecolor=BLACK, linewidth=1.2, zorder=3)
        ax.text(i + dx, l + dy, f"{a[1:]}{THREAT_CODE[t][0]}", ha="center", va="center", fontsize=8, fontweight="bold",
                color=BAND_TEXT[b], zorder=4)
    ax.set_xlim(0.5, 5.5)
    ax.set_ylim(0.5, 5.5)
    ax.set_xticks(range(1, 6))
    ax.set_yticks(range(1, 6))
    ax.set_xlabel("impact (asset value + CIA rating)")
    ax.set_ylabel("likelihood (threat + exposure)")
    ax.set_title("Risk map: 6 assets × 3 attacks")
    ax.text(0.99, 0.01, "label = asset number + BF / SCAN / PE", transform=ax.transAxes, ha="right", va="bottom", fontsize=8, color=GREY)


def p_treatment(ax, assets, threats, exposure):
    """Observed simulated attacks: risk now vs after treatment."""
    xs = np.arange(len(SCENARIOS))
    now, after = [], []
    for sid, a, t, n in SCENARIOS:
        now.append(score(assets.loc[a], threats.loc[t], exposure.loc[a, t], n)[2])
        after.append(score(assets.loc[a], threats.loc[t], max(1, exposure.loc[a, t] - TREATMENT_EXPOSURE_DROP), n)[2])
    w = 0.38
    ax.bar(xs - w / 2, now, w, color=BLACK if plt.rcParams["figure.facecolor"] == "#FFFFFF" else "#F4F4F5", label="current risk")
    ax.bar(xs + w / 2, after, w, color=ORANGE, label="after treatment")
    for x, n_, a_ in zip(xs, now, after):
        ax.text(x - w / 2, n_ + 0.4, str(n_), ha="center", fontsize=10, fontweight="bold")
        ax.text(x + w / 2, a_ + 0.4, str(a_), ha="center", fontsize=10, fontweight="bold", color=ORANGE)
        if n_ != a_:
            ax.text(x, max(n_, a_) + 2.2, f"−{round((n_ - a_) / n_ * 100)}%", ha="center", fontsize=9, color=GREY)
    ax.set_xticks(xs, [f"{s}\n{assets.loc[a, 'hostname']}\n{THREAT_CODE[t]}" for s, a, t, n in SCENARIOS], fontsize=9)
    ax.set_ylim(0, 28)
    ax.set_ylabel("risk score (1-25)")
    ax.set_title("Risk of the six simulated attacks, before and after treatment")
    ax.legend(frameon=False, loc="upper right", ncol=2, fontsize=9)
    ax.text(0.0, -0.3, f"Assumption: a treatment lowers exposure by {TREATMENT_EXPOSURE_DROP} (minimum 1). "
            "Treatments: lockout / key-based login, firewall restriction, least-privilege sudo.",
            transform=ax.transAxes, fontsize=8, color=GREY)


def p_attack_surface(ax, assets, threats, exposure):
    """Total risk per asset across all three attack types (stacked)."""
    rows = []
    for a in assets.index:
        vals = [score(assets.loc[a], threats.loc[t], exposure.loc[a, t])[2] for t in threats.index]
        rows.append((a, vals, sum(vals)))
    rows.sort(key=lambda r: r[2])
    cols = [BLACK if plt.rcParams["figure.facecolor"] == "#FFFFFF" else "#F4F4F5", ORANGE, "#A1A1AA"]
    left = np.zeros(len(rows))
    for j, t in enumerate(threats.index):
        v = np.array([r[1][j] for r in rows])
        ax.barh(range(len(rows)), v, left=left, color=cols[j], label=f"{THREAT_SHORT[t]} ({t})", height=.65)
        for k, (x, w) in enumerate(zip(left, v)):
            ax.text(x + w / 2, k, str(w), ha="center", va="center", fontsize=9, fontweight="bold",
                    color="#FFFFFF" if (j == 0 and cols[0] == BLACK) else BLACK)
        left += v
    for k, r in enumerate(rows):
        ax.text(r[2] + 0.5, k, str(r[2]), va="center", fontsize=10, fontweight="bold")
    ax.set_yticks(range(len(rows)), [label(assets, r[0]) for r in rows])
    ax.set_xlabel("sum of risk scores over the three attack types")
    ax.set_title("Where attacks hurt most: total risk per asset")
    ax.set_xlim(0, max(r[2] for r in rows) + 6)
    ax.legend(frameon=False, fontsize=8.5, loc="lower right")


# --------------------------------------------------------------------- build
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="figures")
    ap.add_argument("--dark", action="store_true")
    ap.add_argument("--dpi", type=int, default=200)
    args = ap.parse_args()

    apply_theme(args.dark)
    assets, threats, exposure = load(args.data)
    os.makedirs(args.out, exist_ok=True)
    save = lambda fig, name: (fig.savefig(os.path.join(args.out, name), dpi=args.dpi, bbox_inches="tight"), plt.close(fig))

    fig, ax = plt.subplots(figsize=(8.5, 6.2))
    p_heatmap(ax, assets, threats, exposure)
    save(fig, "01_attack_impact_heatmap.png")

    fig, axs = plt.subplots(1, 2, figsize=(15, 5.6))
    p_volume(axs[0], assets, threats, exposure, "T1110", 80)
    p_volume(axs[1], assets, threats, exposure, "T1046", 80)
    fig.tight_layout()
    save(fig, "02_risk_vs_attack_volume.png")

    fig, ax = plt.subplots(figsize=(7.5, 6.2))
    p_bubble(ax, assets, threats, exposure)
    save(fig, "03_risk_map.png")

    fig, ax = plt.subplots(figsize=(11, 5.8))
    p_treatment(ax, assets, threats, exposure)
    fig.subplots_adjust(bottom=0.25)
    save(fig, "04_before_after_treatment.png")

    fig, ax = plt.subplots(figsize=(8.5, 5))
    p_attack_surface(ax, assets, threats, exposure)
    save(fig, "05_total_risk_per_asset.png")

    # combined dashboard
    fig = plt.figure(figsize=(22, 13.5))
    gs = fig.add_gridspec(2, 6, hspace=0.55, wspace=1.2)
    p_heatmap(fig.add_subplot(gs[0, 0:2]), assets, threats, exposure)
    p_volume(fig.add_subplot(gs[0, 2:6]), assets, threats, exposure, "T1110", 80)
    p_bubble(fig.add_subplot(gs[1, 0:2]), assets, threats, exposure)
    p_treatment(fig.add_subplot(gs[1, 2:4]), assets, threats, exposure)
    p_attack_surface(fig.add_subplot(gs[1, 4:6]), assets, threats, exposure)
    fig.suptitle("RiskSIEM: what happens to business risk when an attack occurs", fontsize=20, fontweight="bold", x=0.01, ha="left", y=0.97)
    save(fig, "00_risk_analysis_dashboard.png")

    print(f"Saved 6 images in {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()

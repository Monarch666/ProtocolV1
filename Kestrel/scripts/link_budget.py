#!/usr/bin/env python3
"""
Kestrel Protocol — Link Budget Analysis Script
DO-362A (Terrestrial C2) and DO-377A (BLOS/Satellite) Compliance Gate

Computes Free-Space Path Loss, link margin, fade margin → availability,
and checks against DO-362A minimum margin requirements.

Usage:
    python link_budget.py                        # Default 915 MHz / 5 km terrestrial
    python link_budget.py --freq 915e6 --dist 5000 --ptx 30 --prx_min -110
    python link_budget.py --mode blos            # DO-377A satellite budget
    python link_budget.py --help

Exit codes:
    0  All compliance gates PASSED
    1  One or more gates FAILED
"""

import math
import argparse
import sys

# ─── Physical Constants ─────────────────────────────────────────────────────
C_M_S = 299_792_458.0      # Speed of light (m/s)

# ─── DO-362A Compliance Thresholds ─────────────────────────────────────────
DO362A_MIN_LINK_MARGIN_DB  = 6.0    # Minimum link margin for compliance
DO362A_MIN_AVAILABILITY_PC = 99.0   # Minimum link availability (%)
DO362A_MAX_LATENCY_MS      = 100.0  # Maximum C2 message latency (ms), terrestrial

# ─── DO-377A Compliance Thresholds ─────────────────────────────────────────
DO377A_MAX_RTT_MS          = 1500.0 # Maximum round-trip time for BLOS
DO377A_MIN_LINK_MARGIN_DB  = 3.0    # Tighter link budget for satellite (less fade)

# ─── Kestrel Default RF Parameters (COTS 915 MHz link, typical UAV deployment) ─
KESTREL_DEFAULTS = {
    "freq_hz"    : 915e6,    # 915 MHz ISM band (terrestrial default)
    "dist_m"     : 5_000,    # 5 km range
    "ptx_dbm"    : 30.0,     # 30 dBm (1 W) transmit power
    "gtx_dbi"    : 2.0,      # 2 dBi transmit antenna gain
    "grx_dbi"    : 2.0,      # 2 dBi receive antenna gain
    "prx_min_dbm": -110.0,   # Receiver sensitivity (typical LoRa-grade)
    "l_misc_db"  : 3.0,      # Misc losses (cable, connectors, body shadowing)
    "sigma_db"   : 8.0,      # Shadowing standard deviation (suburban environment)
    "latency_ms" : 20.0,     # Typical Kestrel packet RTT over RF (terrestrial)
}

BLOS_DEFAULTS = {
    "freq_hz"    : 1.6e9,    # L-band SATCOM (Iridium / Inmarsat)
    "dist_m"     : 800_000,  # 800 km (LEO satellite altitude)
    "ptx_dbm"    : 37.0,     # 37 dBm (5 W) SATCOM terminal
    "gtx_dbi"    : 12.0,     # 12 dBi directional patch
    "grx_dbi"    : 24.0,     # 24 dBi satellite dish equivalent
    "prx_min_dbm": -130.0,   # Satellite receiver sensitivity
    "l_misc_db"  : 5.0,      # Atmospheric + polarisation + pointing losses
    "sigma_db"   : 4.0,      # Lower sigma for line-of-sight satellite
    "latency_ms" : 750.0,    # One-way latency = 750 ms → RTT = 1500 ms
}


def fspl_db(dist_m: float, freq_hz: float) -> float:
    """Free-Space Path Loss (Friis formula) in dB."""
    if dist_m <= 0 or freq_hz <= 0:
        raise ValueError("Distance and frequency must be positive")
    wavelength = C_M_S / freq_hz
    fspl = (4 * math.pi * dist_m / wavelength) ** 2
    return 10 * math.log10(fspl)


def link_margin_db(ptx_dbm, gtx_dbi, grx_dbi, fspl, l_misc_db, prx_min_dbm) -> float:
    """Link Margin = EIRP + Rx Gain - Path Loss - Misc Losses - Rx Sensitivity."""
    eirp_dbm = ptx_dbm + gtx_dbi
    prx_dbm  = eirp_dbm + grx_dbi - fspl - l_misc_db
    return prx_dbm - prx_min_dbm


def fade_margin_to_availability(margin_db: float, sigma_db: float) -> float:
    """
    Log-normal shadow fading model.
    P(link available) = P(fade < margin) = Φ(margin / σ)
    where Φ is the standard normal CDF (Q-function complement).
    Returns availability as a percentage (0–100).
    """
    if sigma_db <= 0:
        return 100.0
    z = margin_db / sigma_db
    # erfc(x) = 2 * Q(sqrt(2) * x)  →  Φ(z) = 0.5 * erfc(-z / sqrt(2))
    availability = 0.5 * math.erfc(-z / math.sqrt(2))
    return availability * 100.0


def rayleigh_fade_margin(availability_pct: float) -> float:
    """
    Required fade margin (dB) for a target availability under Rayleigh fading.
    FM = -10 * log10(1 - availability)
    """
    a = availability_pct / 100.0
    if a >= 1.0:
        return float('inf')
    return -10 * math.log10(1.0 - a)


def hata_urban_correction(freq_hz: float, dist_m: float) -> float:
    """
    Okumura-Hata correction for urban propagation (supplementary to FSPL).
    Applicable for freq 150–1500 MHz, dist 1–20 km.
    Returns additional attenuation in dB.
    """
    f_mhz = freq_hz / 1e6
    d_km  = dist_m / 1e3
    if not (150 <= f_mhz <= 1500 and 1 <= d_km <= 20):
        return 0.0
    # Hata equation for small/medium city (mobile antenna height 1.5 m)
    a_hm = (1.1 * math.log10(f_mhz) - 0.7) * 1.5 - (1.56 * math.log10(f_mhz) - 0.8)
    hata = (69.55 + 26.16 * math.log10(f_mhz) - 13.82 * math.log10(30)
            - a_hm + (44.9 - 6.55 * math.log10(30)) * math.log10(d_km))
    return max(0.0, hata - fspl_db(dist_m, freq_hz))  # Excess over FSPL


def ascii_margin_chart(params: dict, max_dist_m: float, steps: int = 20) -> str:
    """Generate ASCII chart of link margin vs distance."""
    lines = ["\n  Link Margin vs. Distance", "  " + "─" * 55]
    threshold = DO362A_MIN_LINK_MARGIN_DB

    for i in range(steps + 1):
        d = (max_dist_m / steps) * i
        if d < 1:
            d = 1
        fl = fspl_db(d, params["freq_hz"])
        lm = link_margin_db(params["ptx_dbm"], params["gtx_dbi"], params["grx_dbi"],
                             fl, params["l_misc_db"], params["prx_min_dbm"])
        bar_len = max(0, int((lm + 5) / 2))
        bar_len = min(bar_len, 40)
        bar  = "█" * bar_len
        flag = "✓" if lm >= threshold else "✗"
        lines.append(f"  {d/1000:5.1f}km │{bar:<40}│ {lm:+6.1f} dB {flag}")

    lines.append("  " + "─" * 55)
    lines.append(f"  Compliance threshold: ≥ {threshold:.1f} dB  (DO-362A)")
    return "\n".join(lines)


def run_budget(args) -> bool:
    """Run the full link budget analysis. Returns True if all gates pass."""
    print("\n" + "=" * 65)
    print("  Kestrel Protocol — Link Budget Analysis")
    print(f"  Mode: {'BLOS / DO-377A Satellite' if args.mode == 'blos' else 'Terrestrial / DO-362A'}")
    print("=" * 65)

    p = {
        "freq_hz"    : args.freq,
        "dist_m"     : args.dist,
        "ptx_dbm"    : args.ptx,
        "gtx_dbi"    : args.gtx,
        "grx_dbi"    : args.grx,
        "prx_min_dbm": args.prx_min,
        "l_misc_db"  : args.lmisc,
        "sigma_db"   : args.sigma,
        "latency_ms" : args.latency,
    }

    # ── Core calculations ───────────────────────────────────────────────────
    fspl   = fspl_db(p["dist_m"], p["freq_hz"])
    lm     = link_margin_db(p["ptx_dbm"], p["gtx_dbi"], p["grx_dbi"],
                             fspl, p["l_misc_db"], p["prx_min_dbm"])
    avail  = fade_margin_to_availability(lm, p["sigma_db"])
    fm_req = rayleigh_fade_margin(DO362A_MIN_AVAILABILITY_PC)

    eirp_dbm = p["ptx_dbm"] + p["gtx_dbi"]
    prx_dbm  = eirp_dbm + p["grx_dbi"] - fspl - p["l_misc_db"]

    print(f"\n  ── RF Parameters ───────────────────────────────────────")
    print(f"  Frequency              : {p['freq_hz']/1e6:.1f} MHz")
    print(f"  Link distance          : {p['dist_m']/1000:.2f} km")
    print(f"  Tx power               : {p['ptx_dbm']:.1f} dBm")
    print(f"  Tx antenna gain        : {p['gtx_dbi']:.1f} dBi")
    print(f"  Rx antenna gain        : {p['grx_dbi']:.1f} dBi")
    print(f"  EIRP                   : {eirp_dbm:.1f} dBm")
    print(f"  Rx sensitivity         : {p['prx_min_dbm']:.1f} dBm")
    print(f"  Misc losses            : {p['l_misc_db']:.1f} dB")

    print(f"\n  ── Path Loss Analysis ──────────────────────────────────")
    print(f"  Free-Space Path Loss   : {fspl:.2f} dB")
    print(f"  Received power (Prx)   : {prx_dbm:.2f} dBm")

    print(f"\n  ── Link Quality ────────────────────────────────────────")
    print(f"  Link Margin            : {lm:+.2f} dB")
    print(f"  Shadowing sigma        : {p['sigma_db']:.1f} dB")
    print(f"  Predicted availability : {avail:.3f}%")
    print(f"  Fade margin for 99%    : {fm_req:.2f} dB required")

    # ── Compliance Gates ────────────────────────────────────────────────────
    print(f"\n  ── Compliance Gates ────────────────────────────────────")
    all_pass = True

    if args.mode == "blos":
        rtt = p["latency_ms"] * 2
        gate1 = lm >= DO377A_MIN_LINK_MARGIN_DB
        gate2 = rtt <= DO377A_MAX_RTT_MS
        gate3 = avail >= DO362A_MIN_AVAILABILITY_PC

        status1 = "PASS ✓" if gate1 else "FAIL ✗"
        status2 = "PASS ✓" if gate2 else "FAIL ✗"
        status3 = "PASS ✓" if gate3 else "FAIL ✗"

        print(f"  DO-377A Link Margin ≥ {DO377A_MIN_LINK_MARGIN_DB:.0f} dB : {lm:+.2f} dB → {status1}")
        print(f"  DO-377A RTT ≤ {DO377A_MAX_RTT_MS:.0f} ms        : {rtt:.0f} ms  → {status2}")
        print(f"  Availability ≥ {DO362A_MIN_AVAILABILITY_PC:.0f}%         : {avail:.3f}% → {status3}")
        all_pass = gate1 and gate2 and gate3
    else:
        gate1 = lm >= DO362A_MIN_LINK_MARGIN_DB
        gate2 = avail >= DO362A_MIN_AVAILABILITY_PC
        gate3 = p["latency_ms"] <= DO362A_MAX_LATENCY_MS

        status1 = "PASS ✓" if gate1 else "FAIL ✗"
        status2 = "PASS ✓" if gate2 else "FAIL ✗"
        status3 = "PASS ✓" if gate3 else "FAIL ✗"

        print(f"  DO-362A Link Margin ≥ {DO362A_MIN_LINK_MARGIN_DB:.0f} dB : {lm:+.2f} dB → {status1}")
        print(f"  DO-362A Availability ≥ {DO362A_MIN_AVAILABILITY_PC:.0f}% : {avail:.3f}% → {status2}")
        print(f"  DO-362A Latency ≤ {DO362A_MAX_LATENCY_MS:.0f} ms     : {p['latency_ms']:.0f} ms → {status3}")
        all_pass = gate1 and gate2 and gate3

    # ── ASCII Chart ─────────────────────────────────────────────────────────
    print(ascii_margin_chart(p, p["dist_m"] * 2))

    # ── Summary ─────────────────────────────────────────────────────────────
    print(f"\n  {'ALL COMPLIANCE GATES PASSED' if all_pass else 'ONE OR MORE COMPLIANCE GATES FAILED'}")
    print("=" * 65 + "\n")

    return all_pass


def main():
    parser = argparse.ArgumentParser(
        description="Kestrel Link Budget — DO-362A / DO-377A Compliance Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python link_budget.py                              # Default 915 MHz / 5 km
  python link_budget.py --dist 10000                 # 10 km range
  python link_budget.py --mode blos                  # Satellite / BLOS
  python link_budget.py --freq 868e6 --ptx 27 --dist 3000
        """
    )
    parser.add_argument("--mode",    choices=["terrestrial", "blos"], default="terrestrial")
    parser.add_argument("--freq",    type=float, help="Carrier frequency (Hz)")
    parser.add_argument("--dist",    type=float, help="Link distance (m)")
    parser.add_argument("--ptx",     type=float, help="Tx power (dBm)")
    parser.add_argument("--gtx",     type=float, help="Tx antenna gain (dBi)")
    parser.add_argument("--grx",     type=float, help="Rx antenna gain (dBi)")
    parser.add_argument("--prx_min", type=float, help="Rx sensitivity (dBm)")
    parser.add_argument("--lmisc",   type=float, help="Misc losses (dB)")
    parser.add_argument("--sigma",   type=float, help="Shadowing std-dev (dB)")
    parser.add_argument("--latency", type=float, help="One-way latency (ms)")
    args = parser.parse_args()

    # Apply mode defaults then override with explicit CLI args
    defaults = BLOS_DEFAULTS if args.mode == "blos" else KESTREL_DEFAULTS
    for key in ("freq", "dist", "ptx", "gtx", "grx", "prx_min", "lmisc", "sigma", "latency"):
        map_ = {"freq": "freq_hz", "dist": "dist_m", "ptx": "ptx_dbm",
                "gtx": "gtx_dbi", "grx": "grx_dbi", "prx_min": "prx_min_dbm",
                "lmisc": "l_misc_db", "sigma": "sigma_db", "latency": "latency_ms"}
        if getattr(args, key) is None:
            setattr(args, key, defaults[map_[key]])

    passed = run_budget(args)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()

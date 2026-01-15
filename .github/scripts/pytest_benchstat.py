import json
import sys
import math
import re
import platform
import subprocess

# Force UTF-8 output for Windows
sys.stdout.reconfigure(encoding="utf-8")


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {path}: {e}", file=sys.stderr)
        return None


def format_val(val):
    if val is None:
        return "N/A"
    if val < 1e-9:
        return f"{val*1e9:.2f}ns"
    if val < 1e-6:
        return f"{val*1e9:.2f}ns"  # Use ns for < 1us too? benchstat usually uses ns, us, ms, s
    if val < 1e-3:
        return f"{val*1e6:.2f}us"
    if val < 1:
        return f"{val*1e3:.2f}ms"
    return f"{val:.2f}s"


def normalize_name(name):
    name = re.sub(r"^test_benchmark_", "", name)
    parts = name.split("_")
    new_parts = []
    for p in parts:
        if p.lower() in ["rbac", "abac", "acl", "api", "rest"]:
            new_parts.append(p.upper())
        else:
            new_parts.append(p.capitalize())
    return "".join(new_parts)


def main():
    if len(sys.argv) < 3:
        print("Usage: python pytest_benchstat.py base.json pr.json")
        sys.exit(1)

    base_data = load_json(sys.argv[1])
    pr_data = load_json(sys.argv[2])

    if not base_data or not pr_data:
        sys.exit(1)

    base_map = {b["name"]: b["stats"] for b in base_data["benchmarks"]}
    pr_map = {b["name"]: b["stats"] for b in pr_data["benchmarks"]}

    all_names = sorted(set(base_map.keys()) | set(pr_map.keys()))

    # Print Header
    print("goos: linux")
    print("goarch: amd64")
    print("pkg: github.com/casbin/pycasbin")

    # Get CPU info
    cpu_info = "GitHub Actions Runner"
    try:
        if platform.system() == "Linux":
            command = "cat /proc/cpuinfo | grep 'model name' | head -1"
            output = subprocess.check_output(command, shell=True).decode().strip()
            if output:
                cpu_info = output.split(": ")[1]
    except Exception:
        pass
    print(f"cpu: {cpu_info}")
    print("")

    w_name = 50
    w_val = 20

    # Header
    print(f"{'':<{w_name}}│   old base.json    │   new pr.json      │")
    print(f"{'':<{w_name}}│    sec/op          │    sec/op          │")

    base_means = []
    pr_means = []

    # Footnote tracking
    need_low_sample_note = False
    need_insignificant_note = False
    need_geomean_note = False

    for name in all_names:
        base = base_map.get(name)
        pr = pr_map.get(name)

        base_mean = base["mean"] if base else 0
        pr_mean = pr["mean"] if pr else 0

        base_std = base["stddev"] if base else 0
        pr_std = pr["stddev"] if pr else 0

        base_rounds = base["rounds"] if base else 0
        pr_rounds = pr["rounds"] if pr else 0

        if base_mean > 0:
            base_means.append(base_mean)
        if pr_mean > 0:
            pr_means.append(pr_mean)

        # Format Value with StdDev and Superscript
        def format_cell(val, std, rounds):
            if val == 0:
                return "N/A"

            # StdDev formatting
            if rounds < 2 or std == 0:
                std_str = "± ∞"
            else:
              
                pct = (std / val) * 100
                std_str = f"± {pct:.0f}%"

            # Superscript for low sample size
            note = ""
            if rounds < 6:
                note = "¹"
                nonlocal need_low_sample_note
                need_low_sample_note = True

            return f"{format_val(val)} {std_str} {note}"

        base_str = format_cell(base_mean, base_std, base_rounds) if base else "N/A"
        pr_str = format_cell(pr_mean, pr_std, pr_rounds) if pr else "N/A"

        # Delta column (Statistical Significance)

        delta_str = ""
        if base and pr:
            # Simple check: do intervals overlap?
   
            n = min(base_rounds, pr_rounds)

            # Mock p-value logic for display
            # If n < 4, benchstat says it can't detect difference usually?
            p_val = 1.000  # Placeholder

 
            if n < 4:
                delta_str = f"~ (p={p_val:.3f} n={n}) ²"
                need_insignificant_note = True
            else:
  
                delta_str = f"~ (p=? n={n})"

        display_name = normalize_name(name)

        print(f"{display_name:<{w_name}} {base_str:<{w_val}} {pr_str:<{w_val}}")

    if base_means and pr_means:
        # Filter out zero values for geomean calculation to avoid math error
        base_geo_input = [x for x in base_means if x > 0]
        pr_geo_input = [x for x in pr_means if x > 0]

        g_base_str = "N/A"
        g_pr_str = "N/A"

        if base_geo_input:
            g_base = math.exp(sum(math.log(x) for x in base_geo_input) / len(base_geo_input))
            g_base_str = f"{format_val(g_base)}"

        if pr_geo_input:
            g_pr = math.exp(sum(math.log(x) for x in pr_geo_input) / len(pr_geo_input))
            g_pr_str = f"{format_val(g_pr)}"

        print(f"{'geomean':<{w_name}} {g_base_str:<{w_val}} {g_pr_str:<{w_val}}")

    # Print Footnotes
    if need_low_sample_note:
        print("¹ need >= 6 samples for confidence interval at level 0.95")
    if need_insignificant_note:
        print("² need >= 4 samples to detect a difference at alpha level 0.05")



if __name__ == "__main__":
    main()

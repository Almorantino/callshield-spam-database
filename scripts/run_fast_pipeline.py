import subprocess
import sys


def run_step(name, command):
    print(f"\n▶ {name}")
    result = subprocess.run(command, shell=True)

    if result.returncode != 0:
        print(f"❌ Step failed: {name}")
        sys.exit(result.returncode)

    print(f"✓ Completed: {name}")


def main():

    run_step(
        "Generate numbers from prefixes",
        "python3 scripts/generate_numbers_from_prefix.py"
    )

    run_step(
        "Merge generated numbers into raw dataset",
        "python3 scripts/merge_generated_numbers.py"
    )

    run_step(
        "Build scoring with existing cluster context",
        "python3 scripts/build_spam_database.py"
    )

    run_step(
        "Update freshness scores",
        "python3 scripts/update_freshness_scores.py"
    )

    run_step(
        "Purge stale numbers",
        "python3 scripts/purge_stale_numbers.py"
    )

    run_step(
        "Refresh cluster analysis",
        "python3 scripts/analyze_number_clusters.py"
    )

    run_step(
        "Select dataset for CallKit",
        "python3 scripts/select_callkit_dataset.py"
    )

    print("\n⚡ Fast pipeline completed successfully")


if __name__ == "__main__":
    main()

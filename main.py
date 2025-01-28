import os
import orjson  # Faster JSON parsing library
from multiprocessing import Pool, Value, Lock, cpu_count
from packaging.version import Version, InvalidVersion


def is_version_affected(version_to_check, affected_versions):
    """
    Determines if a given version is affected based on the affected version ranges.
    Supports direct version matches and range checks (e.g., >=, <=, >, <).
    
    Args:
        version_to_check (str): The version to check.
        affected_versions (list): List of version range dictionaries from the CVE JSON.

    Returns:
        bool: True if the version is affected, False otherwise.
    """
    for version_entry in affected_versions:
        version_range = version_entry["version"]

        if version_range.lower() == "n/a":  # Skip non-applicable versions
            continue

        if version_range.startswith("="):  # Direct version match
            try:
                if Version(version_to_check) == Version(version_range[1:].strip()):
                    return True
            except InvalidVersion:
                continue

        elif any(op in version_range for op in (">=", "<=", "<", ">")):  # Range checks
            try:
                parts = version_range.split(",")
                is_affected = True
                for part in parts:
                    part = part.strip()
                    if part.startswith(">=") and Version(version_to_check) < Version(part[2:].strip()):
                        is_affected = False
                    elif part.startswith("<=") and Version(version_to_check) > Version(part[2:].strip()):
                        is_affected = False
                    elif part.startswith("<") and Version(version_to_check) >= Version(part[1:].strip()):
                        is_affected = False
                    elif part.startswith(">") and Version(version_to_check) <= Version(part[1:].strip()):
                        is_affected = False
                if is_affected:
                    return True
            except InvalidVersion:
                continue

        else:  # Direct version check without operator
            try:
                if Version(version_to_check) == Version(version_range.strip()):
                    return True
            except InvalidVersion:
                continue

    return False


def process_files_batch(file_info_list):
    """
    Processes a batch of CVE JSON files to search for affected products and versions.

    Args:
        file_info_list (list): List of tuples containing file paths, program names, and versions.

    Returns:
        list: List of tuples containing CVE IDs and their base scores.
    """
    program_name, version_to_check = file_info_list[0][1:]
    results = []

    for file_path, _, _ in file_info_list:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                cve_json = orjson.loads(file.read())

                affected_list = cve_json.get("containers", {}).get("cna", {}).get("affected", [])
                for affected in affected_list:
                    product = affected.get("product", "").strip().lower()
                    versions = affected.get("versions", [])

                    if program_name.lower() == product and is_version_affected(version_to_check, versions):
                        base_score = None
                        metrics = cve_json.get("containers", {}).get("cna", {}).get("metrics", [])
                        for metric in metrics:
                            if "cvssV3_1" in metric:
                                base_score = metric["cvssV3_1"].get("baseScore", None)
                            if base_score is None and "cvssV4_0" in metric:
                                base_score = metric["cvssV4_0"].get("baseScore", "None")
                            if base_score is not None:
                                break

                        cve_id = cve_json["cveMetadata"]["cveId"]
                        results.append((cve_id, base_score))
                        break
        except Exception:
            continue

    return results


def search_cve_data(base_path, program_name, version_to_check):
    """
    Searches for CVEs in a specified database path using multiprocessing for efficiency.

    Args:
        base_path (str): Path to the CVE database.
        program_name (str): Name of the program to search for.
        version_to_check (str): Version of the program to check.

    Returns:
        list: List of found CVEs with their base scores.
    """
    file_list = [
        (os.path.join(root, file_name), program_name, version_to_check)
        for root, _, files in os.walk(base_path)
        for file_name in files if file_name.endswith(".json")
    ]

    total_files = len(file_list)
    print(f"Files to process: {total_files}")

    batch_size = 100
    batches = [file_list[i:i + batch_size] for i in range(0, len(file_list), batch_size)]

    progress = Value("i", 0)
    progress_lock = Lock()
    results = []

    def update_progress(batch_result, batch_size):
        with progress_lock:
            progress.value += batch_size
            print(f"\rProgress: {progress.value}/{total_files} files processed", end="")
        results.extend(batch_result)

    with Pool(processes=cpu_count()) as pool:
        for batch in batches:
            pool.apply_async(process_files_batch, args=(batch,), callback=lambda r, b=len(batch): update_progress(r, b))

        pool.close()
        pool.join()

    print(f"\nSearch complete: {len(results)} CVEs found.")
    return results


if __name__ == "__main__":
    base_path = "./"
    program_name = input("Program name: ").strip()
    version_to_check = input("Program version: ").strip()

    found_cves = search_cve_data(base_path, program_name, version_to_check)

    print("\nFound CVEs:")
    for cve_id, base_score in found_cves:
        print(f"{cve_id} cvss: {base_score}")

    if not found_cves:
        print("\nNo affected CVEs found.")
    else:
        print(f"\nTotal {len(found_cves)} CVEs found.")

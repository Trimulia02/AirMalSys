import json
import os
import glob
from pathlib import Path
from cvss import CVSS4

# Mapping TTP ID ke update CVSS vector
TTP_TO_VECTOR = {
    "T1070.004": {"VI": "H", "SI": "H", "VC": "H"},
    "T1082": {"VC": "H", "VI": "L"},
    "T1497.001": {"VC": "H", "SI": "H", "SC": "H", "AV": "L"},
    "T1547.001": {"VI": "H", "SI": "H", "AT": "P"},
    "T1059.003": {"VC": "H", "VI": "H", "UI": "N"},
    "T1490": {"VA": "H", "VI": "H", "SA": "H"},
    "T1112": {"VI": "H", "SC": "H"},
    "T1491.001": {"VC": "L", "UI": "N"}
}

def find_latest_report():
    paths = glob.glob("/home/cuckoo/.cuckoocwd/storage/analyses/*/*/task_1/report.json")
    if not paths:
        print("[!] Gagal membaca report.json: tidak ditemukan jalur yang cocok.")
        return None
    latest = max(paths, key=os.path.getmtime)
    print(f"[DEBUG] Menggunakan report.json terbaru: {latest}")
    return latest

def update_vector_from_ttps(ttps_list, current_vector):
    for ttp_id in ttps_list:
        mapping = TTP_TO_VECTOR.get(ttp_id)
        if mapping:
            current_vector.update(mapping)
    return current_vector

def generate_vector_from_signatures(signatures):
    base_vector = {
        "AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N",
        "VC": "L", "VI": "L", "VA": "L", "SC": "L", "SI": "L", "SA": "L",
        "S": "N", "R": "U", "V": "D"
    }

    for sig in signatures:
        name = sig.get("name", "").lower()
        score = sig.get("score", 0)
        print(f"[DEBUG] Memproses signature: {name}, score: {score}")

        if score >= 8:
            base_vector.update({
                "VC": "H", "VI": "H", "VA": "H",
                "SC": "H", "SI": "H", "SA": "H"
            })

        if "adjustprivilege" in name or "token" in name:
            base_vector.update({"PR": "L", "VI": "H", "SC": "H", "AT": "P"})

        if "wrote_proc_memory" in name or "inject" in name:
            base_vector.update({"AC": "L", "VC": "H", "VI": "H", "UI": "N"})

        if "drop" in name or "file_drops" in name or "executes_dropped_exe" in name:
            base_vector.update({"VI": "H", "VA": "H", "SC": "H", "R": "A"})

        if "loads_dropped_dll" in name:
            base_vector.update({"VC": "H", "VI": "H", "SI": "H", "AC": "L"})

        if "registry_write_runkey" in name or "registry_changes_wallpaper" in name:
            base_vector.update({"VI": "L", "SI": "L", "PR": "L", "UI": "N"})

        if "registry_writes_large_value" in name:
            base_vector.update({"VI": "H", "VA": "L", "SC": "H"})

        if "ransom" in name or "encrypt" in name or "deletes_shadow_copies" in name:
            base_vector.update({
                "VA": "H", "VI": "H", "SI": "H",
                "S": "N",  # Ganti dari L atau C ke N (safe & valid)
                "R": "C"
            })

        if "keylogger" in name or "screenshot" in name:
            base_vector.update({"VC": "H", "UI": "P"})

        if "cmd_attrib_hidden" in name:
            base_vector.update({"VC": "L", "VI": "L", "UI": "N", "S": "N"})

        if "files_creates_shortcut" in name:
            base_vector.update({"VI": "L", "UI": "A"})

        ttps = sig.get("ttps", [])
        base_vector = update_vector_from_ttps(ttps, base_vector)

    # Pastikan nilai-nilai vektor valid sesuai CVSS4 yang didukung pustaka
    VALID_VALUES = {
        "AV": {"N", "A", "L", "P"},
        "AC": {"L", "H"},
        "AT": {"N", "P"},
        "PR": {"N", "L", "H"},
        "UI": {"N", "P", "A"},
        "VC": {"N", "L", "H"},
        "VI": {"N", "L", "H"},
        "VA": {"N", "L", "H"},
        "SC": {"N", "L", "H"},
        "SI": {"N", "L", "H"},
        "SA": {"N", "L", "H"},
        "S": {"N"},       # ❗ Hanya nilai N yang valid dalam lib ini
        "R": {"U", "A", "C"},
        "V": {"D", "X"}
    }

    # Filter nilai invalid
    for k, v in base_vector.items():
        if v not in VALID_VALUES.get(k, {"X"}):
            print(f"[WARN] Nilai tidak valid: {k}:{v} -> diganti jadi default {list(VALID_VALUES[k])[0]}")
            base_vector[k] = list(VALID_VALUES[k])[0]

    keys = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA",
            "SC", "SI", "SA", "S", "R", "V"]
    vector_str = "CVSS:4.0/" + "/".join(f"{k}:{base_vector[k]}" for k in keys)
    print(f"[DEBUG] Final CVSS4 Vector: {vector_str}")
    return vector_str

def main():
    report_path = find_latest_report()
    if not report_path or not os.path.exists(report_path):
        print("[!] Gagal membaca report.json: file tidak ditemukan atau jalur tidak valid.")
        return

    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except Exception as e:
        print(f"[!] Gagal membaca report.json: {e}")
        return

    signatures = report.get("signatures", [])
    if not signatures:
        print("[!] Tidak ada signature yang ditemukan dalam laporan.")
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/S:N/R:N/V:D"
    else:
        vector = generate_vector_from_signatures(signatures)

    try:
        cvss = CVSS4(vector)
        score = cvss.base_score
    except Exception as e:
        print(f"[!] Gagal menghitung CVSS dari vektor '{vector}': {e}")
        score = 0.0

    output_path = Path("/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt")
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(f"{score:.1f}\n")
        print(f"[+] CVSS Score berhasil disimpan: {score:.1f} di {output_path}")
    except Exception as e:
        print(f"[!] Gagal menyimpan skor CVSS ke {output_path}: {e}")

if __name__ == "__main__":
    main()

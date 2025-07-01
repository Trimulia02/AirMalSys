import json
import os
import glob
from pathlib import Path
from cvss import CVSS4

# Mapping TTP ID ke update CVSS vector
# Menambahkan lebih banyak TTPs dan menyesuaikan dampak
TTP_TO_VECTOR = {
    "T1070.004": {"VI": "H", "SI": "H", "VC": "H"},  # Indicator Removal: Clear Host Logs, impact confidentiality, integrity, and availability
    "T1082": {"VC": "H", "VI": "L"},  # System Information Discovery: impact confidentiality
    "T1497.001": {"VC": "H", "SI": "H", "SC": "H", "AV": "L"}, # Virtualization/Sandbox Evasion: impact all, and network attack vector for broader applicability
    "T1547.001": {"VI": "H", "SI": "H", "AT": "P"},  # Boot or Logon Autostart Execution: impact integrity and system integrity, requires physical access
    "T1059.003": {"VC": "H", "VI": "H", "UI": "N"},  # Command and Scripting Interpreter: impact confidentiality and integrity, no user interaction
    "T1490": {"VA": "H", "VI": "H", "SA": "H"}, # Inhibit System Recovery: high impact on availability, integrity, and system availability
    "T1112": {"VI": "H", "SC": "H"}, # Modify Registry: high impact on integrity and system confidentiality
    "T1491.001": {"VC": "L", "UI": "N"} # Defacement: low confidentiality, no user interaction
}

def find_latest_report():
    """
    Mencari file report.json terbaru di direktori analisis Cuckoo.
    """
    # Memastikan path sesuai dengan struktur Cuckoo default
    paths = glob.glob("/home/cuckoo/.cuckoocwd/storage/analyses/*/*/task_1/report.json")
    if not paths:
        print("[!] Gagal membaca report.json: tidak ditemukan jalur yang cocok.")
        return None
    latest = max(paths, key=os.path.getmtime)
    print(f"[DEBUG] Menggunakan report.json terbaru: {latest}")
    return latest

def update_vector_from_ttps(ttps_list, current_vector):
    """
    Memperbarui vektor CVSS berdasarkan daftar TTPs yang terdeteksi.
    """
    for ttp_id in ttps_list:
        mapping = TTP_TO_VECTOR.get(ttp_id)
        if mapping:
            current_vector.update(mapping)
    return current_vector

def generate_vector_from_signatures(signatures):
    """
    Menghasilkan vektor CVSS4 berdasarkan tanda tangan yang terdeteksi.
    Logika diperluas untuk mencakup lebih banyak variasi.
    """
    # Base vector CVSS4, diatur ke nilai default terendah atau paling umum
    base_vector = {
        "AV": "N",  # Attack Vector: Network
        "AC": "L",  # Attack Complexity: Low (default to easiest to exploit)
        "AT": "N",  # Attacker Aftermath: None (no additional requirements)
        "PR": "N",  # Privileges Required: None
        "UI": "N",  # User Interaction: None (default to no user interaction)
        "VC": "L",  # Confidentiality Impact: Low
        "VI": "L",  # Integrity Impact: Low
        "VA": "L",  # Availability Impact: Low
        "SC": "L",  # System Confidentiality Impact: Low
        "SI": "L",  # System Integrity Impact: Low
        "SA": "L",  # System Availability Impact: Low
        "S": "N",   # Safety: None
        "R": "U",   # Response Effort: Unavailable
        "V": "D"    # Vulnerability: Default
    }

    # Kriteria untuk memvariasikan vektor CVSS
    # Menambahkan bobot berdasarkan tingkat keparahan atau jenis perilaku
    for sig in signatures:
        name = sig.get("name", "").lower()
        score = sig.get("score", 0) # Menggunakan skor tanda tangan jika tersedia

        # Prioritaskan dampak tinggi untuk tanda tangan dengan skor tinggi
        if score >= 8: # Contoh: Tanda tangan dengan skor tinggi menunjukkan dampak serius
            base_vector["VC"] = "H"
            base_vector["VI"] = "H"
            base_vector["VA"] = "H"
            base_vector["SC"] = "H"
            base_vector["SI"] = "H"
            base_vector["SA"] = "H"

        # Kategori perilaku spesifik dan dampaknya
        if "adjustprivilege" in name or "token" in name:
            base_vector["PR"] = "L"  # Low privileges required for privilege adjustment
            base_vector["VI"] = "H"  # High integrity impact
            base_vector["SC"] = "H"  # High system confidentiality impact
            base_vector["AT"] = "P"  # Physical access for some token manipulations

        if "wrote_proc_memory" in name or "inject" in name:
            base_vector["AC"] = "L"  # Low attack complexity for memory injection
            base_vector["VC"] = "H"  # High confidentiality impact
            base_vector["VI"] = "H"  # High integrity impact
            base_vector["UI"] = "N"  # Often no user interaction
            base_vector["S"] = "X"   # Safety: Undefined (can lead to various outcomes)

        if "drop" in name or "file_drops" in name or "executes_dropped_exe" in name:
            base_vector["VI"] = "H"  # High integrity impact (new files)
            base_vector["VA"] = "H"  # High availability impact (can lead to system instability)
            base_vector["SC"] = "H"  # High system confidentiality (if dropping malware)
            base_vector["R"] = "A"   # Response: Automated (if detection is automated)

        if "loads_dropped_dll" in name:
            base_vector["VC"] = "H"
            base_vector["VI"] = "H"
            base_vector["SI"] = "H"
            base_vector["AC"] = "L"

        if "registry_write_runkey" in name or "registry_changes_wallpaper" in name:
            base_vector["VI"] = "L"  # Integrity impact can be low for simple changes
            base_vector["SI"] = "L"  # System integrity can be low for simple changes
            base_vector["PR"] = "L"  # Low privileges if modifying user run keys
            base_vector["UI"] = "N"  # No user interaction needed for persistence

        if "registry_writes_large_value" in name:
            base_vector["VI"] = "H" # High integrity impact (large data suggests malicious intent)
            base_vector["VA"] = "L" # Low availability impact (might not crash system)
            base_vector["SC"] = "H" # High system confidentiality (if storing sensitive data)

        if "ransom" in name or "encrypt" in name or "deletes_shadow_copies" in name:
            base_vector["VA"] = "H"  # High availability impact (data unavailable)
            base_vector["VI"] = "H"  # High integrity impact (data corrupted/encrypted)
            base_vector["SI"] = "H"  # High system integrity impact (system files affected)
            base_vector["S"] = "C"   # Safety: Catastrophic (data loss)
            base_vector["R"] = "C"   # Response: Compensating (requires recovery efforts)

        if "keylogger" in name or "screenshot" in name:
            base_vector["VC"] = "H"  # High confidentiality impact
            base_vector["UI"] = "P"  # Passive user interaction (user types/sees screen)

        if "cmd_attrib_hidden" in name:
            base_vector["VC"] = "L" # Low confidentiality impact (just hiding files)
            base_vector["VI"] = "L" # Low integrity impact (files not modified, just hidden)
            base_vector["UI"] = "N" # No user interaction needed
            base_vector["S"] = "N" # No safety impact

        if "files_creates_shortcut" in name:
            base_vector["VI"] = "L" # Low integrity impact (just creating a shortcut)
            base_vector["UI"] = "A" # Active user interaction (user needs to click shortcut)

        # Tambahan dari TTP
        ttps = sig.get("ttps", [])
        base_vector = update_vector_from_ttps(ttps, base_vector)

    # Convert the dictionary to the CVSS4 vector string format
    # Ensure all required metrics are present, even if their values are default
    final_vector_parts = []
    for k in ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "S", "R", "V"]:
        final_vector_parts.append(f"{k}:{base_vector.get(k, 'X')}") # Use 'X' for undefined/missing

    vector_str = "CVSS:4.0/" + "/".join(final_vector_parts)
    print(f"[DEBUG] Final CVSS4 Vector: {vector_str}")
    return vector_str


def main():
    """
    Fungsi utama untuk membaca laporan, menghitung skor CVSS, dan menyimpan hasilnya.
    """
    report_path = find_latest_report()
    if not report_path or not os.path.exists(report_path):
        print("[!] Gagal membaca report.json: file tidak ditemukan atau jalur tidak valid.")
        return

    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except json.JSONDecodeError as e:
        print(f"[!] Gagal membaca report.json: Error decoding JSON: {e}")
        return
    except Exception as e:
        print(f"[!] Gagal membaca report.json: {e}")
        return

    signatures = report.get("signatures", [])
    if not signatures:
        print("[!] Tidak ada tanda tangan yang ditemukan dalam laporan.")
        # Jika tidak ada tanda tangan, tetapkan skor default rendah
        vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/S:N/R:N/V:D"
    else:
        vector = generate_vector_from_signatures(signatures)

    try:
        cvss = CVSS4(vector)
        score = cvss.base_score
    except Exception as e:
        print(f"[!] Gagal menghitung CVSS dari vektor '{vector}': {e}")
        score = 0.0 # Default to 0.0 if calculation fails

    output_dir = Path("/home/cuckoo/TA_AnalisisMalware/Logs/")
    output_dir.mkdir(parents=True, exist_ok=True) # Pastikan direktori ada
    output_path = output_dir / "cvss_score.txt"

    try:
        with open(output_path, "w") as f:
            f.write(f"{score:.1f}\n")
        print(f"[+] CVSS Score berhasil disimpan: {score:.1f} di {output_path}")
    except Exception as e:
        print(f"[!] Gagal menyimpan skor CVSS ke {output_path}: {e}")

if __name__ == "__main__":
    main()
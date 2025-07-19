import os
import json
import glob
from cvss import CVSS4

REPORT_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
OUTPUT_FILE = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"

def find_latest_report():
    paths = glob.glob("/home/cuckoo/.cuckoocwd/storage/analyses/*/*/task_1/report.json")
    if not paths:
        print("[!] Gagal membaca report.json: tidak ditemukan jalur yang cocok.")
        return None
    latest = max(paths, key=os.path.getmtime)
    print(f"[DEBUG] Menggunakan report.json terbaru: {latest}")
    return latest

def map_signature_to_cvss(signature):
    name = signature.get("name", "").lower()
    vector = {}

    # Mapping berbasis keyword signature
    if any(k in name for k in ["ransom", "encrypt", "mimikatz", "credential", "inject", "hook", "keylogger"]):
        vector.update({"VC": "H", "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "H"})
    elif any(k in name for k in ["registry", "winlogon", "autorun", "boot"]):
        vector.update({"VC": "L", "VI": "L", "VA": "L", "SC": "L"})
    elif any(k in name for k in ["executes", "schtasks", "powershell"]):
        vector.update({"VC": "L", "VA": "L", "SA": "L", "SI": "L"})
    elif "memory" in name or "dump" in name:
        vector.update({"VI": "H", "SI": "L"})

    # Access vector hints
    if "remote" in name or "network" in name:
        vector.update({"AV": "N", "AC": "L", "PR": "N", "UI": "N"})
    elif "local" in name or "disk" in name:
        vector.update({"AV": "L", "AC": "L", "PR": "L", "UI": "N"})

    return vector

def map_ttp_to_cvss(ttp):
    vector = {}
    tactics = ttp.get("tactics", [])
    techniques = ttp.get("techniques", [])

    # Mapping berbasis MITRE TTP
    for tactic in tactics:
        tactic = tactic.lower()
        if tactic in ["execution", "persistence", "privilege escalation"]:
            vector.update({"PR": "L", "SA": "H"})
        if tactic in ["defense evasion", "collection"]:
            vector.update({"SC": "L", "SI": "H"})
        if tactic in ["exfiltration", "impact"]:
            vector.update({"VC": "H", "VI": "H", "SC": "H"})

    for tech in techniques:
        tid = tech.get("id", "")
        if tid in ["T1059", "T1055"]:  # Command/script execution, Process injection
            vector.update({"AT": "P", "SA": "H", "SI": "H"})
        if tid.startswith("T1003"):  # Credential dumping
            vector.update({"VI": "H", "SI": "H"})

    return vector

def map_network_to_cvss(network):
    vector = {}

    if "udp" in network or "tcp" in network:
        vector.update({"AV": "N", "AC": "L", "PR": "N", "UI": "N"})

    if "http" in network or "https" in network:
        vector.update({"VC": "L", "SC": "L"})

    if "dns" in network:
        vector.update({"V": "D", "S": "N"})

    if "irc" in network or "smtp" in network or "ftp" in network:
        vector.update({"VI": "H", "SA": "H", "SC": "H"})

    return vector

def combine_vectors(vectors):
    combined = {}
    
    # Metrik dampak (impact metrics)
    for metric in ["VC", "VI", "VA", "SC", "SI", "SA"]:
        highest = "N"
        for v in vectors:
            val = v.get(metric, "N")
            if val == "H":
                highest = "H"
                break
            elif val == "L" and highest == "N":
                highest = "L"
        combined[metric] = highest

    # Metrik lainnya dengan default fallback
    defaults = {
        "AV": "N",
        "AC": "L",
        "AT": "N",
        "PR": "N",
        "UI": "N"
    }
    for key in defaults:
        found = next((v.get(key) for v in vectors if key in v), None)
        combined[key] = found if found else defaults[key]

    return combined

def main():
    report_path = find_latest_report()
    if not report_path:
        print("[-] Tidak ditemukan report.json terbaru.")
        return

    with open(report_path, "r") as f:
        report = json.load(f)

    vectors = []

    # Signatures
    for sig in report.get("signatures", []):
        vec = map_signature_to_cvss(sig)
        if vec:
            print(f"[DEBUG] Signature: {sig.get('name')} -> {vec}")
            vectors.append(vec)

    # TTP
    if "ttp" in report:
        vec = map_ttp_to_cvss(report["ttp"])
        if vec:
            print(f"[DEBUG] TTP Vector: {vec}")
            vectors.append(vec)

    # Network
    if "network" in report:
        vec = map_network_to_cvss(report["network"])
        if vec:
            print(f"[DEBUG] Network Vector: {vec}")
            vectors.append(vec)

    if not vectors:
        print("[-] Tidak ada data vektor untuk dihitung.")
        return

    final_vector = combine_vectors(vectors)
    vector_str = "CVSS:4.0/" + "/".join([f"{k}:{v}" for k, v in final_vector.items()])
    print(f"[DEBUG] Final CVSS4 Vector: {vector_str}")

    cvss = CVSS4(vector_str)
    score = round(cvss.scores()[0], 1)

    with open(OUTPUT_FILE, "w") as out:
        out.write(str(score))

    print(f"[+] CVSS Score berhasil disimpan: {score} di {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

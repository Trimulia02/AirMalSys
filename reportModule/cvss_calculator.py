#!/usr/bin/env python3
import os
import glob
import json
from datetime import datetime
from cvss import CVSS4
import ast

CVSS_SCORE_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"


def find_latest_report():
    paths = glob.glob("/home/cuckoo/.cuckoocwd/storage/analyses/*/*/task_1/report.json")
    if not paths:
        print("[!] Gagal membaca report.json: tidak ditemukan jalur yang cocok.")
        return None
    latest = max(paths, key=os.path.getmtime)
    print(f"[DEBUG] Menggunakan report.json terbaru: {latest}")
    return latest

def analyze_signatures(signatures):
    vector = {
        "VC": "N", "VI": "N", "VA": "N",
        "SC": "N", "SI": "N", "SA": "N",
        "V": "U",
        "AV": "L", "AC": "H", "PR": "H",
        "UI": "A",  
        "S": "N",
        "AT": "N"
    }

    signature_mapping = {
        "antianalysis_debugger_devices": {"SA": "L", "AC": "L"},
        "checks_ip_web": {"SA": "L"},
        "cmd_attrib_hidden": {"SC": "L", "SA": "L"},
        "cmd_netsh_advfirewall": {"SA": "L"},
        "cmd_sc_autostart": {"SC": "L", "PR": "L"},
        "cmd_sc_config": {"SC": "L", "PR": "L"},
        "cmd_sc_config_disable": {"SC": "L", "PR": "L"},
        "cmd_sc_create": {"SC": "L", "PR": "L"},
        "cmd_sc_delete": {"SC": "L", "PR": "L"},
        "cmd_sc_start": {"SC": "L", "PR": "L"},
        "cmd_sc_stop": {"SC": "L", "PR": "L"},
        "cmd_schtasks_create": {"SC": "L", "PR": "L"},
        "cmd_stratum_crypto": {"VA": "H", "AC": "L"},
        "cmd_taskkill_process": {"SC": "L"},
        "cmd_timeout_delay": {"SA": "L"},
        "deletes_itself": {"SA": "L"},
        "deletes_shadow_copies": {
            "VC": "H", "VI": "H", "VA": "L", "SC": "H", "SI": "H",
            "SA": "L", "PR": "L", "UI": "N", "AC": "L"
        },
        "executes_dropped_exe": {"VA": "H", "AC": "L", "UI": "N"},
        "file_drops_startup": {"PR": "L"},
        "file_drops_system32": {"PR": "L"},
        "file_drops_windows": {"PR": "L"},
        "files_antiav_general": {"SA": "L"},
        "files_antivm_disk_devices": {"SA": "L", "AC": "L"},
        "files_antivm_virtualbox": {"SA": "L", "AC": "L"},
        "files_antivm_vmware": {"SA": "L", "AC": "L"},
        "files_creates_office_doc": {"VA": "L"},
        "files_creates_shortcut": {"PR": "L"},
        "files_cuckoo_sandbox": {"SA": "L"},
        "files_drops_exe_general": {"VA": "H"},
        "files_drops_exe_user": {"VA": "H"},
        "flawedammyy": {"VC": "H", "VI": "H", "PR": "L"},
        "infostealer_browser_data": {
            "VC": "H", "VI": "H", "SC": "L", "SI": "L", "PR": "L", "UI": "N", "V": "D"
        },
        "infostealer_email_clients": {
            "VC": "H", "VI": "H", "SC": "L", "SI": "L", "PR": "L", "UI": "N", "V": "D"
        },
        "infostealer_ftp_data": {
            "VC": "H", "VI": "H", "SC": "L", "SI": "L", "PR": "L", "UI": "N", "V": "D"
        },
        "loads_driver": {"PR": "L"},
        "loads_dropped_dll": {"VA": "H", "AC": "L", "UI": "N"},
        "njrat": {"VC": "H", "VI": "H", "SC": "H", "SI": "H", "PR": "L"},
        "process_injection": {"SI": "H", "VC": "L", "SC": "H", "PR": "L"},
        "process_other_parent": {"SA": "L"},
        "registry_antivm_bios_check": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_cpu_check": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_hyperv": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_ide_disks": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_scsi_id": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_virtualbox": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_antivm_vmware": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_bypasses_uac": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_bypasses_windows_security": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_changes_wallpaper": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_checks_nation_code": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_checks_uninstall_keys": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_defender_realtime_prot": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_disables_auto_update": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_disables_regedit": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_disables_system_restore": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_disables_taskmgr": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_file_extension_vis": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_modifies_browser_security": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_modifies_browser_warnings": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_modifies_file_vis": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_modifies_firewall_policy": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_sets_ie_homepage": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_winlogon_persistence": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_write_executable": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_write_powershell": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_write_runkey": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_writes_appinit_dlls": {"SC": "L", "SA": "L", "PR": "L"},
        "registry_writes_large_value": {"SC": "L", "SA": "L", "PR": "L"},
        "remcos": {"VC": "H", "VI": "H", "PR": "L"},
        "susevent_adjustprivilegetoken": {"PR": "L"},
        "susevent_mapviewofsection": {"SA": "L"},
        "susevent_setthreadcontext": {"SA": "L"},
        "susevent_unmapmainimage": {"SA": "L"},
        "thread_hidefromdebugger": {"SA": "L"},
        "warzone": {"VC": "H", "VI": "H", "SC": "H", "SI": "H", "PR": "L"},
        "wrote_proc_memory": {"SI": "H", "VC": "L", "SC": "H", "PR": "L"},
        "xmrig": {"VA": "H", "AC": "L"}
    }

    for sig in signatures:
        name = sig.get("name", "").lower()
        if name in signature_mapping:
            vector.update(signature_mapping[name])

    return vector

def analyze_ttps_seq(ttps_seq):
    vector = {}

    ttp_mapping = {
        "T1005": {"VC": "H", "VI": "H"},  # Data from Local System
        "T1012": {"SC": "L", "SA": "L"},  # Query Registry
        "T1053.005": {"SC": "L", "PR": "L"},  # Scheduled Task
        "T1055": {"SI": "H", "SC": "H"},  # Process Injection
        "T1059.001": {"SA": "H", "AC": "L"},  # PowerShell
        "T1059.003": {"SA": "H", "AC": "L"},  # Windows Command Shell
        "T1070.004": {"SA": "L"},  # File Deletion
        "T1082": {"VC": "L", "SA": "L"},  # System Information Discovery
        "T1112": {"SC": "L", "SA": "L"},  # Modify Registry
        "T1134.004": {"SI": "H"},  # Token Impersonation/Theft
        "T1489": {"VC": "H", "SI": "H"},  # Service Stop
        "T1490": {"VC": "H", "SI": "H"},  # Inhibit System Recovery
        "T1491.001": {"SA": "L"},  # Defacement: Internal
        "T1497.001": {"SA": "H"},  # System Checks (anti-vm)
        "T1497.003": {"SA": "H"},  # Time Based Evasion
        "T1518": {"SA": "L"},  # Software Discovery
        "T1518.001": {"SA": "L"},  # Security Software Discovery
        "T1546.010": {"SC": "L", "PR": "L"},  # AppInit DLLs
        "T1547.001": {"SC": "L", "PR": "L"},  # Registry Run Keys
        "T1547.004": {"SC": "L", "PR": "L"},  # Winlogon Helper DLL
        "T1548.002": {"PR": "L"},  # Bypass User Account Control
        "T1552.001": {"VI": "H", "SC": "H", "SI": "H"},  # Credential Dumping
        "T1562.001": {"SA": "H"},  # Disable or Modify Tools
        "T1562.004": {"SA": "H"},  # Disable Windows Event Logging
        "T1562.006": {"SA": "H"},  # Indicator Blocking
        "T1564.001": {"SA": "H"},  # Hidden Files and Directories
        "T1569.002": {"SA": "H"}  # Service Execution
    }

    if not ttps_seq:
        return vector

    for ttp in ttps_seq:
        mapping = ttp_mapping.get(ttp.upper())
        if mapping:
            vector.update(mapping)

    return vector

def analyze_dns_udp_host(report):
    vector = {}

    # DNS queries
    dns_queries = report.get("dns_queries_seq", []) or report.get("dns", {}).get("dns", [])
    if isinstance(dns_queries, str):
        try:
            dns_queries = ast.literal_eval(dns_queries)
        except Exception:
            dns_queries = []
    if isinstance(dns_queries, list) and any(".host" in d or "pipedream" in d or "ddns" in d for d in dns_queries):
        vector.update({
            "VC": "H",   # Confidentiality impact
            "V": "D"     # Proven exploit
        })

    if any("mega.nz" in d or "bitbucket" in d or ".onion" in d for d in dns_queries):
        vector.update({
            "VC": "H",
            "V": "D"
        })

    network = report.get("network", {})
    if "udp" in network and network["udp"]:
        vector.update({
            "AV": "N",   # Network access
            "V": "D"
        })

    return vector

def build_vector(base_vector):
    parts = [f"{k}:{v}" for k, v in base_vector.items()]
    return "CVSS:4.0/" + "/".join(sorted(parts))

def main():
    report_path = find_latest_report()
    if not report_path:
        print("[-] Tidak ditemukan report.json terbaru.")
        return

    try:
        with open(report_path, "r") as f:
            report = json.load(f)

        sig_vector = analyze_signatures(report.get("signatures", []))
        ttp_vector = analyze_ttps_seq(report.get("ttp", []))
        net_vector = analyze_dns_udp_host(report)

        combined_vector = {**sig_vector, **ttp_vector, **net_vector}
        vector_str = build_vector(combined_vector)
        print(f"[DEBUG] Final CVSS4 Vector: {vector_str}")

        cvss = CVSS4(vector_str)
        score = cvss.scores()[0]

        with open(CVSS_SCORE_PATH, "w") as f:
            f.write(f"{score:.1f}")
        print(f"[+] CVSS Score berhasil disimpan: {score:.1f} di {CVSS_SCORE_PATH}")

    except Exception as e:
        print(f"[!] Gagal menghitung CVSS Score: {e}")

if __name__ == "__main__":
    main()
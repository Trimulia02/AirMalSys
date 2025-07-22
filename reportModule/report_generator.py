#!/usr/bin/env python3
import os
import json
import logging
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, LongTable, TableStyle, PageBreak, Frame, PageTemplate
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.units import cm
from reportlab.platypus import Spacer
from reportlab.lib.styles import ParagraphStyle


# --- KONFIGURASI ---
ANALYSIS_DIR = "/home/cuckoo/.cuckoocwd/storage/analyses"
REPORT_DIR = "/home/cuckoo/TA_AnalisisMalware/Report"
ML_RESULT_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/ml_results.txt"
CVSS_SCORE_PATH = "/home/cuckoo/TA_AnalisisMalware/Logs/cvss_score.txt"

# --- PALET WARNA & GAYA ---
COLOR_PRIMARY_DARK = colors.HexColor("#2C3E50")
COLOR_PRIMARY = colors.HexColor("#3498DB")
COLOR_ACCENT = colors.HexColor("#E74C3C")
COLOR_LIGHT_GREY = colors.HexColor("#ECF0F1")
COLOR_MEDIUM_GREY = colors.HexColor("#BDC3C7")
COLOR_TEXT = colors.HexColor("#34495E")

def find_latest_analysis():
    """Menemukan report.json dan analysis.json terbaru berdasarkan mtime."""
    latest_report = None
    latest_analysis = None
    latest_time = 0

    for root, _, files in os.walk(ANALYSIS_DIR):
        if "report.json" in files:
            report_path = os.path.join(root, "report.json")
            mtime = os.path.getmtime(report_path)

            if mtime > latest_time:
                # Coba cari analysis.json satu atau dua level di atas
                candidate_analysis_1 = os.path.abspath(os.path.join(report_path, "../../analysis.json"))
                candidate_analysis_2 = os.path.abspath(os.path.join(report_path, "../../../analysis.json"))

                if os.path.exists(candidate_analysis_1):
                    latest_analysis = candidate_analysis_1
                    latest_report = report_path
                    latest_time = mtime
                elif os.path.exists(candidate_analysis_2):
                    latest_analysis = candidate_analysis_2
                    latest_report = report_path
                    latest_time = mtime

    if latest_report and latest_analysis:
        return latest_report, latest_analysis

    logging.warning("Tidak dapat menemukan laporan analisis yang valid.")
    return None

def read_ml_results():
    """Membaca hasil klasifikasi dari file teks."""
    if not os.path.exists(ML_RESULT_PATH):
        return "Tidak Diketahui", "Tidak Diketahui", "-"
    try:
        with open(ML_RESULT_PATH, "r") as f:
            lines = [line.strip() for line in f.readlines()]
            if len(lines) >= 3:
                jenis = "Malware" if "malware" in lines[0].lower() else "Benign"
                probab = f"{float(lines[1]) * 100:.1f}%"
                family = lines[2] if lines[2] else "-"
                return jenis, family, probab
            elif len(lines) >= 2:
                jenis = "Malware" if "malware" in lines[0].lower() else "Benign"
                probab = f"{float(lines[1]) * 100:.1f}%"
                return jenis, "-", probab
    except Exception as e:
        logging.error(f"Error membaca hasil ML: {e}")
    return "Tidak Diketahui", "Tidak Diketahui", "-"

def read_cvss_score():
    """Membaca skor CVSS dari file teks."""
    try:
        with open(CVSS_SCORE_PATH, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "-"
    except Exception as e:
        logging.error(f"Error membaca skor CVSS: {e}")
        return "-"

def get_cvss_severity(score_str):
    """Mengonversi skor CVSS numerik menjadi tingkat keparahan (severity)."""
    try:
        score = float(score_str)
        if score == 0:
            return "None"
        elif 0.1 <= score <= 3.9:
            return "Low"
        elif 4.0 <= score <= 6.9:
            return "Medium"
        elif 7.0 <= score <= 8.9:
            return "High"
        elif 9.0 <= score <= 10.0:
            return "Critical"
        else:
            return "Unknown"
    except (ValueError, TypeError):
        return "N/A"
from datetime import datetime, timezone, timedelta

def format_timestamp(ts):
    """Memformat timestamp ISO 8601 dari Cuckoo menjadi waktu lokal (WIB)."""
    try:
        # Ubah string ISO ke objek datetime dengan timezone UTC
        dt_utc = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        # Konversi ke zona waktu WIB (UTC+7)
        dt_wib = dt_utc.astimezone(timezone(timedelta(hours=7)))
        return dt_wib.strftime("%Y-%m-%d %H:%M:%S WIB")
    except (AttributeError, ValueError):
        return str(ts)

# --- FUNGSI PEMBUATAN PDF ---
class ReportPDFTemplate(PageTemplate):
    """Template untuk mengatur header dan footer pada setiap halaman."""
    def __init__(self, id, doc):
        self.doc = doc
        frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
        super().__init__(id, [frame])

    def beforeDrawPage(self, canvas, doc):
        """Dipanggil sebelum halaman digambar."""
        # Header
        canvas.saveState()
        canvas.setFillColor(COLOR_PRIMARY_DARK)
        canvas.setFont('Helvetica-Bold', 12)
        canvas.drawString(doc.leftMargin, A4[1] - 1.5 * cm, "Malware Analysis Report")
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(COLOR_TEXT)
        canvas.drawRightString(A4[0] - doc.rightMargin, A4[1] - 1.5 * cm, f"Created on: {datetime.now().strftime('%Y-%m-%d')}")
        canvas.setStrokeColor(COLOR_LIGHT_GREY)
        canvas.line(doc.leftMargin, A4[1] - 1.8 * cm, A4[0] - doc.rightMargin, A4[1] - 1.8 * cm)
        canvas.restoreState()

        # Footer
        canvas.saveState()
        canvas.setStrokeColor(COLOR_LIGHT_GREY)
        canvas.line(doc.leftMargin, doc.bottomMargin - 0.2 * cm, A4[0] - doc.rightMargin, doc.bottomMargin - 0.2 * cm)
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(COLOR_MEDIUM_GREY)
        canvas.drawCentredString(A4[0] / 2, doc.bottomMargin - 0.6 * cm, f"Page {doc.page}")
        canvas.restoreState()

def create_styled_table(data, col_widths):
    """Membuat tabel dengan gaya yang sudah ditentukan."""
    tbl = LongTable(data, colWidths=col_widths)
    style = TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, 0), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_PRIMARY_DARK),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING', (0, 0), (-1, 0), 8),
        
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('TEXTCOLOR', (0, 1), (-1, -1), COLOR_TEXT),
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_MEDIUM_GREY),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
    ])
    tbl.setStyle(style)
    return tbl

def add_signature_table_with_narrative(report_data, elements, style_h2, style_table_cell, style_table_header):
    """Menambahkan tabel signature dengan narasi ke PDF."""

    signature_narrative = {
        "antianalysis_debugger_devices": "Detects presence of debugger-related devices as an anti-analysis method.",
        "checks_ip_web": "Performs IP or web-based checks, potentially for environment awareness.",
        "cmd_attrib_hidden": "Uses 'attrib +h' to hide files or folders, a common evasion technique.",
        "cmd_netsh_advfirewall": "Modifies firewall settings via 'netsh advfirewall', possibly to allow malicious traffic.",
        "cmd_sc_autostart": "Attempts to configure services to start automatically upon boot.",
        "cmd_sc_config": "Modifies configuration of existing system services.",
        "cmd_sc_config_disable": "Disables certain system services, potentially security-related.",
        "cmd_sc_create": "Creates new services to gain persistence or execute payloads.",
        "cmd_sc_delete": "Deletes system services to disrupt normal operations or hide activity.",
        "cmd_sc_start": "Attempts to start previously created or modified services.",
        "cmd_sc_stop": "Stops system services which may interfere with malware.",
        "cmd_schtasks_create": "Creates scheduled tasks to ensure persistence or timed execution.",
        "cmd_stratum_crypto": "Detected use of Stratum protocol, often linked to crypto-mining.",
        "cmd_taskkill_process": "Kills processes, possibly to disable security tools.",
        "cmd_timeout_delay": "Delays execution using 'timeout', possibly to evade sandboxes.",
        "deletes_itself": "Attempts self-deletion to remove traces post-execution.",
        "deletes_shadow_copies": "Deletes shadow copies to hinder system recovery.",
        "executes_dropped_exe": "Executes dropped executable files to initiate payloads.",
        "file_drops_startup": "Drops files in startup locations to gain persistence.",
        "file_drops_system32": "Drops files in System32 directory, often requiring elevated privileges.",
        "file_drops_windows": "Drops files in Windows directory for stealth or persistence.",
        "files_antiav_general": "Targets antivirus software using general anti-AV techniques.",
        "files_antivm_disk_devices": "Detects disk devices to determine if running in virtual machine.",
        "files_antivm_virtualbox": "Checks for VirtualBox-specific files to detect virtual environment.",
        "files_antivm_vmware": "Detects VMware artifacts as anti-VM technique.",
        "files_creates_office_doc": "Creates Office document files, possibly for phishing.",
        "files_creates_shortcut": "Creates shortcut (.lnk) files for persistence or social engineering.",
        "files_cuckoo_sandbox": "Detects Cuckoo sandbox files, used to evade analysis.",
        "files_drops_exe_general": "Drops general executable files, likely payloads.",
        "files_drops_exe_user": "Drops executables in user directory for execution or persistence.",
        "flawedammyy": "Detects activity related to FlawedAmmyy RAT.",
        "infostealer_browser_data": "Steals sensitive browser data such as cookies, history, or saved credentials.",
        "infostealer_email_clients": "Targets email clients to extract credentials or messages.",
        "infostealer_ftp_data": "Attempts to steal FTP credentials or connection data.",
        "loads_driver": "Loads kernel-mode drivers, which may indicate privilege escalation.",
        "loads_dropped_dll": "Loads dropped DLLs into memory for execution.",
        "njrat": "Detects behavior related to njRAT remote access trojan.",
        "process_injection": "Injects code into another process for stealthy execution.",
        "process_other_parent": "Spawns processes with suspicious or uncommon parent process.",
        "registry_antivm_bios_check": "Queries BIOS keys to detect virtual environments.",
        "registry_antivm_cpu_check": "Checks registry entries related to CPU for anti-VM.",
        "registry_antivm_hyperv": "Detects Microsoft Hyper-V registry keys.",
        "registry_antivm_ide_disks": "Checks IDE disk signatures to identify virtual drives.",
        "registry_antivm_scsi_id": "Looks for SCSI IDs typical of virtual machines.",
        "registry_antivm_virtualbox": "Detects VirtualBox registry values.",
        "registry_antivm_vmware": "Detects VMware presence via registry.",
        "registry_bypasses_uac": "Modifies registry to bypass User Account Control.",
        "registry_bypasses_windows_security": "Disables or bypasses Windows Security via registry edits.",
        "registry_changes_wallpaper": "Modifies wallpaper settings, possibly for defacement.",
        "registry_checks_nation_code": "Inspects regional settings from registry, potentially for geo-fencing.",
        "registry_checks_uninstall_keys": "Checks uninstall registry keys, possibly for software enumeration.",
        "registry_defender_realtime_prot": "Disables Windows Defender’s real-time protection via registry.",
        "registry_disables_auto_update": "Turns off automatic updates via registry.",
        "registry_disables_regedit": "Prevents Registry Editor from launching.",
        "registry_disables_system_restore": "Disables System Restore features.",
        "registry_disables_taskmgr": "Prevents Task Manager from launching.",
        "registry_file_extension_vis": "Modifies registry to hide or show file extensions.",
        "registry_modifies_browser_security": "Lowers browser security via registry settings.",
        "registry_modifies_browser_warnings": "Disables browser warnings using registry.",
        "registry_modifies_file_vis": "Changes settings for hidden files visibility.",
        "registry_modifies_firewall_policy": "Alters firewall rules or policies.",
        "registry_sets_ie_homepage": "Changes Internet Explorer homepage.",
        "registry_winlogon_persistence": "Adds persistence using Winlogon registry keys.",
        "registry_write_executable": "Writes executable path into registry.",
        "registry_write_powershell": "Injects PowerShell commands into registry keys.",
        "registry_write_runkey": "Uses Run key to gain persistence on reboot.",
        "registry_writes_appinit_dlls": "Uses AppInit_DLLs to load malicious DLLs.",
        "registry_writes_large_value": "Writes suspiciously large registry values.",
        "remcos": "Detects behavior matching Remcos RAT family.",
        "susevent_adjustprivilegetoken": "Adjusts privilege tokens, often for escalation.",
        "susevent_mapviewofsection": "Performs memory mapping of sections between processes.",
        "susevent_setthreadcontext": "Modifies thread execution context, often for injection.",
        "susevent_unmapmainimage": "Unmaps the main executable image, common in hollowing.",
        "thread_hidefromdebugger": "Uses API to hide thread from debugger.",
        "warzone": "Behavior consistent with Warzone RAT activity.",
        "wrote_proc_memory": "Writes directly into memory of another process.",
        "xmrig": "Detected XMRig crypto miner activity."
    }

    sigs = report_data.get("signatures", [])
    if not sigs:
        return

    elements.append(Paragraph("Detected Signatures", style_h2))
    sig_data = [[
        Paragraph("No.", style_table_header),
        Paragraph("Signature", style_table_header),
        Paragraph("Name", style_table_header),
        Paragraph("Description", style_table_header)
    ]]

    for idx, sig in enumerate(sigs, 1):
        sig_id = sig.get("name", "-")
        sig_name = sig.get("description", "-")
        desc = signature_narrative.get(sig_id, "This signature was triggered during analysis, but no detailed explanation is available.")
        sig_data.append([
            Paragraph(str(idx), style_table_cell),
            Paragraph(sig_id, style_table_cell),
            Paragraph(sig_name, style_table_cell),
            Paragraph(desc, style_table_cell)
        ])

    sig_table = create_styled_table(sig_data, col_widths=[1.5*cm, 4*cm, 6*cm, None])
    elements.append(sig_table)
    elements.append(Spacer(1, 12))

def add_process_tree_table(report_data, elements, style_h2, style_table_cell, style_table_header):
    """Menambahkan tabel pohon proses (process tree) ke laporan PDF."""
    processes = report_data.get("processes", {}).get("process_list", [])
    if not isinstance(processes, list) or not processes:
        print("[DEBUG] Tidak ada proses yang ditemukan.")
        return

    print(f"[DEBUG] Jumlah proses ditemukan: {len(processes)}")

    elements.append(Paragraph("Process Tree", style_h2))
    table_data = [[
        Paragraph("No", style_table_header),
        Paragraph("Process Name", style_table_header),
        Paragraph("PID", style_table_header),
        Paragraph("PPID", style_table_header),
        Paragraph("Command Line", style_table_header),
 ]]

    for idx, proc in enumerate(processes, 1):
        name = proc.get("name", "-")
        pid = proc.get("pid", "-")
        ppid = proc.get("ppid", "-")
        cmd = proc.get("commandline", "-")

        table_data.append([
            Paragraph(str(idx), style_table_cell),
            Paragraph(name, style_table_cell),
            Paragraph(str(pid), style_table_cell),
            Paragraph(str(ppid), style_table_cell),
            Paragraph(cmd, style_table_cell),
        ])

    table = create_styled_table(table_data, col_widths=[1.2*cm, 3.5*cm, 2*cm, 2*cm, 7*cm, 2.5*cm])
    elements.append(table)
    elements.append(Spacer(1, 12))

def add_mitre_ttp_table(report_data, elements, style_h2, style_table_cell, style_table_header):
    """Menambahkan tabel TTP MITRE (dengan narasi penjelasan) ke PDF."""

    # Mapping deskripsi naratif TTP
    ttp_descriptions = {
        "T1005": "The malware accessed or collected files and data from the local system.",
        "T1012": "The malware queried the Windows registry to gather configuration or security settings.",
        "T1053.005": "A scheduled task was created or manipulated by the malware to maintain persistence or execute payloads.",
        "T1055": "The malware attempted process injection to execute its code within another process.",
        "T1059.001": "The malware executed commands via PowerShell scripting.",
        "T1059.003": "Malware executed shell commands using the Windows command interpreter (cmd.exe).",
        "T1070.004": "Malware deleted files to cover its tracks and hinder forensic analysis.",
        "T1082": "The malware collected information about the operating system and hardware.",
        "T1112": "Registry keys or values were modified by the malware to hide its presence or achieve persistence.",
        "T1134.004": "The malware spoofed the parent process ID to disguise its origin and evade detection.",
        "T1489": "The malware attempted to stop critical services, potentially to disable protection mechanisms.",
        "T1490": "System recovery features were disabled or deleted by the malware to prevent rollback.",
        "T1491.001": "Malware defaced internal system visuals or user-facing content.",
        "T1497.001": "The malware performed checks to detect virtualized environments and avoid execution in sandboxes.",
        "T1497.003": "The malware delayed execution or used time-based triggers to evade analysis.",
        "T1518": "Malware attempted to discover installed software to better understand the host system.",
        "T1518.001": "Security-related software was specifically identified by the malware.",
        "T1546.010": "Malware used AppInit DLLs to load malicious code into running processes.",
        "T1547.001": "The malware created or modified registry keys to ensure execution at startup.",
        "T1547.004": "Malware injected DLLs into the Winlogon process to maintain persistence.",
        "T1548.002": "Malware bypassed User Account Control (UAC) to escalate privileges.",
        "T1552.001": "The malware dumped credentials from memory or storage to gain unauthorized access.",
        "T1562.001": "Security tools were disabled or modified to avoid detection or interruption.",
        "T1562.004": "Windows event logging was disabled to hinder post-infection auditing.",
        "T1562.006": "Indicators of compromise were blocked or hidden by the malware.",
        "T1564.001": "Malware concealed files or directories to avoid detection.",
        "T1569.002": "The malware executed via registered Windows services."
    }

    ttps = report_data.get("ttps", [])
    if not ttps:
        return

    elements.append(Paragraph("Detected MITRE TTPs", style_h2))
    ttp_data = [[
        Paragraph("No.", style_table_header),
        Paragraph("TTPs", style_table_header),
        Paragraph("Name", style_table_header),
        Paragraph("Description", style_table_header)
    ]]

    for idx, ttp_entry in enumerate(ttps, 1):
        ttp_id = ttp_entry.get("id", "-")
        ttp_name = ttp_entry.get("name", "-")
        description = ttp_descriptions.get(ttp_id, "This technique was used by the malware but no detailed explanation is available.")
        ttp_data.append([
            Paragraph(str(idx), style_table_cell),
            Paragraph(ttp_id, style_table_cell),
            Paragraph(ttp_name, style_table_cell),
            Paragraph(description, style_table_cell)
        ])

    ttp_table = create_styled_table(ttp_data, col_widths=[1.5*cm, 3*cm, 5*cm, None])
    elements.append(ttp_table)
    elements.append(Spacer(1, 12))

def add_dns_query_table(report_data, elements, style_h2, style_table_cell, style_table_header):
    """Menambahkan tabel DNS Query ke laporan PDF dengan deskripsi naratif dan tanpa duplikasi."""
    dns_section = report_data.get("dns")
    if not isinstance(dns_section, dict):
        print("[DEBUG] DNS data bukan dict.")
        return

    dns_queries = dns_section.get("query", [])
    if not isinstance(dns_queries, list) or not dns_queries:
        print("[DEBUG] DNS data kosong atau bukan list.")
        return

    print(f"[DEBUG] Jumlah DNS queries ditemukan: {len(dns_queries)}")

    # Deskripsi berdasarkan domain
    domain_descriptions = {
        "update.microsoft.com": "Used by Windows Update service to check for and download updates.",
        "cloudapp.net": "Commonly used by Microsoft Azure services and virtual machines.",
        "settings-win.data.microsoft.com": "Used by Windows for telemetry and settings sync.",
        "sls.update.microsoft.com": "Used by Microsoft's Software Licensing Service.",
        "blockchain.info": "Public blockchain domain; may indicate crypto-related activity.",
        "bing.com": "Microsoft search engine domain, typically benign.",
        "windows.com": "Core Microsoft infrastructure domain, typically safe.",
        "microsoft.com": "General Microsoft domain, commonly used by Windows components.",
        "google.com": "Google services, typically accessed by browsers or apps."
    }

    elements.append(Paragraph("Observed DNS Queries", style_h2))
    table_data = [[
        Paragraph("No", style_table_header),
        Paragraph("Domain IP", style_table_header),
        Paragraph("Domain", style_table_header),
        Paragraph("Description", style_table_header)
    ]]

    seen_entries = set()  # Untuk menyimpan kombinasi unik (domain, dst_ip)

    for idx, entry in enumerate(dns_queries, 1):
        domain = entry.get("name", "-")
        dst_ip = entry.get("dstip", "-")
        unique_key = (domain, dst_ip)

        if unique_key in seen_entries:
            continue  # Lewati jika sudah pernah ditampilkan
        seen_entries.add(unique_key)

        matched_desc = "-"
        for known in domain_descriptions:
            if domain.endswith(known):
                matched_desc = domain_descriptions[known]
                break
        else:
            matched_desc = "Unrecognized domain queried by the malware during execution."

        table_data.append([
            Paragraph(str(len(seen_entries)), style_table_cell),
            Paragraph(dst_ip, style_table_cell),
            Paragraph(domain, style_table_cell),
            Paragraph(matched_desc, style_table_cell)
        ])

    if len(table_data) == 1:
        print("[DEBUG] Tidak ada DNS query unik untuk ditampilkan.")
        return

    table = create_styled_table(table_data, col_widths=[1.5*cm, 4*cm, 6*cm, None])
    elements.append(table)
    elements.append(Spacer(1, 12))

def add_udp_table(report_data, elements, style_h2, style_table_cell, style_table_header):
    """Menambahkan tabel aktivitas UDP ke laporan PDF dengan deskripsi dan tanpa duplikasi."""
    udp_data = report_data.get("network", {}).get("udp", [])
    if not isinstance(udp_data, list) or not udp_data:
        print("[DEBUG] UDP data kosong atau bukan list.")
        return

    print(f"[DEBUG] Jumlah UDP entries ditemukan: {len(udp_data)}")

    elements.append(Paragraph("Observed UDP Traffic", style_h2))
    table_data = [[
        Paragraph("No", style_table_header),
        Paragraph("Source IP", style_table_header),
        Paragraph("Destination IP", style_table_header),
        Paragraph("Port", style_table_header),
        Paragraph("Description", style_table_header)
    ]]

    seen_udp = set()

    for entry in udp_data:
        src_ip = entry.get("srcip", "-")
        dst_ip = entry.get("dstip", "-")
        dst_port = entry.get("dstport", "-")
        key = (src_ip, dst_ip, dst_port)

        if key in seen_udp:
            continue
        seen_udp.add(key)

        # Penjelasan naratif
        if dst_ip.startswith("239.") or dst_ip.endswith(".255"):
            desc = "Local broadcast/multicast traffic for device or name discovery."
        elif dst_port == 137:
            desc = "NetBIOS Name Service (NBNS) — used in Windows for name resolution."
        elif dst_port == 138:
            desc = "NetBIOS Datagram Service — used for LAN broadcast messages."
        elif dst_port == 53:
            desc = "DNS query over UDP — used to resolve domain names."
        else:
            desc = "Unusual UDP communication observed, purpose unclear."

        table_data.append([
            Paragraph(str(len(seen_udp)), style_table_cell),
            Paragraph(src_ip, style_table_cell),
            Paragraph(dst_ip, style_table_cell),
            Paragraph(str(dst_port), style_table_cell),
            Paragraph(desc, style_table_cell)
        ])

    if len(table_data) == 1:
        print("[DEBUG] Tidak ada entri UDP unik yang ditampilkan.")
        return

    table = create_styled_table(table_data, col_widths=[1.5*cm, 4*cm, 4*cm, 2*cm, None])
    elements.append(table)
    elements.append(Spacer(1, 12))

def add_summary_section(report_data, elements, style_h2, style_paragraph):
    """Menambahkan ringkasan analisis ke laporan PDF dalam bentuk naratif menyeluruh."""
    elements.append(Paragraph("Summary", style_h2))

    processes = report_data.get("processes", {}).get("process_list", [])
    dns_queries = report_data.get("dns", {}).get("query", [])
    udp_data = report_data.get("network", {}).get("udp", [])
    ttps = report_data.get("ttps", [])
    signatures = report_data.get("signatures", [])

    total_processes = len(processes)
    total_dns = len(dns_queries)
    total_udp = len(udp_data)
    total_ttps = len(ttps)
    total_sigs = len(signatures)

    # DNS suspicious check
    known_domains = ["microsoft.com", "windows.com", "google.com", "update.microsoft.com", "cloudapp.net", "bing.com"]
    suspicious_domains = set()
    for query in dns_queries:
        domain = query.get("name", "")
        if not any(domain.endswith(k) for k in known_domains):
            suspicious_domains.add(domain)
    suspicious_dns = bool(suspicious_domains)

    # Persistence indicators
    reg_keywords = ["Run", "Winlogon", "Shell", "StickyKeys"]
    persistence_detected = False
    schtask_detected = False
    for proc in processes:
        cmd = proc.get("commandline", "").lower()
        if "schtasks" in cmd:
            schtask_detected = True
            persistence_detected = True
        if any(k.lower() in cmd for k in reg_keywords):
            persistence_detected = True

    # Tulis narasi
    summary = f"The malware sample initiated a total of {total_processes} process{'es' if total_processes != 1 else ''}, suggesting "
    summary += "moderate to high system interaction. " if total_processes >= 7 else "minimal to moderate system activity. "

    if total_sigs:
        summary += f"A total of {total_sigs} behavioral signatures were triggered, indicating potential malicious actions across different categories. "

    if total_ttps:
        summary += f"{total_ttps} MITRE ATT&CK techniques were identified, covering tactics such as "
        summary += ', '.join(sorted(set(t.get("name", "-") for t in ttps))[:3])
        summary += " and possibly more. "

    if suspicious_dns:
        sample_dns = ', '.join(list(suspicious_domains)[:3])
        summary += f"DNS traffic analysis revealed queries to suspicious domains such as {sample_dns}, which may indicate outbound communication to C2 servers or external payload hosts. "
    else:
        summary += "All DNS queries were directed toward known and trusted domains, reducing the likelihood of C2 involvement. "

    if total_udp:
        summary += f"The network layer showed {total_udp} UDP traffic entries, including "
        udp_desc = []
        for u in udp_data:
            if u["dstport"] == 53:
                udp_desc.append("DNS over UDP")
            elif u["dstport"] == 137:
                udp_desc.append("NetBIOS name service")
            elif str(u["dstip"]).startswith("239.") or str(u["dstip"]).endswith(".255"):
                udp_desc.append("multicast/broadcast")
        summary += ', '.join(set(udp_desc) or ["unusual UDP activity"]) + ". "

    if persistence_detected:
        summary += "Persistence techniques were observed, such as registry modifications or scheduled tasks. "
        if schtask_detected:
            summary += "The presence of 'schtasks' implies that the malware schedules tasks for execution at logon. "
    else:
        summary += "There were no clear indicators of persistence mechanisms such as registry alterations or scheduled tasks. "

    if total_ttps == 0 and total_sigs == 0 and total_udp == 0 and not suspicious_dns:
        summary += "Overall, the sample exhibited relatively low threat behavior with limited indicators of compromise. "

    elements.append(Paragraph(summary.strip(), style_paragraph))

def add_mitigation_guidance(family, elements, style_h2, style_body):
    """Adds mitigation and response advice based on malware family."""
    guidance_map = {
        "ransomware": (
            "<b>Malware Family Detected:</b> Ransomware<br/><br/>"
            "<b>Prevention:</b><br/>"
            "• Regularly back up data and store it offline or in secure cloud storage.<br/>"
            "• Keep operating systems and antivirus software up to date.<br/>"
            "• Avoid opening suspicious email attachments or links.<br/>"
            "• Disable macros in Microsoft Office documents.<br/>"
            "• Apply least-privilege principles and segment networks.<br/><br/>"
            "<b>Response:</b><br/>"
            "• Immediately isolate infected systems from the network.<br/>"
            "• Do not pay the ransom.<br/>"
            "• Engage incident response or security professionals.<br/>"
            "• Restore from clean, verified backups.<br/>"
            "• Report to cybersecurity authorities or law enforcement."
        ),
        "rat": (
            "<b>Malware Family Detected:</b> Remote Access Trojan (RAT)<br/><br/>"
            "<b>Prevention:</b><br/>"
            "• Use firewalls to block unauthorized access.<br/>"
            "• Monitor network traffic and system behavior.<br/>"
            "• Apply system and application updates regularly.<br/><br/>"
            "<b>Response:</b><br/>"
            "• Disconnect the system from the internet.<br/>"
            "• Perform a full antivirus scan.<br/>"
            "• Remove startup entries and registry changes related to the RAT.<br/>"
            "• Change all affected account passwords."
        ),
        "keylogger": (
            "<b>Malware Family Detected:</b> Keylogger<br/><br/>"
            "<b>Prevention:</b><br/>"
            "• Use real-time antivirus/anti-malware protection.<br/>"
            "• Avoid pirated or cracked software.<br/>"
            "• Use two-factor authentication (2FA).<br/><br/>"
            "<b>Response:</b><br/>"
            "• Immediately change sensitive passwords.<br/>"
            "• Identify and remove unknown programs.<br/>"
            "• Perform a scan in Safe Mode if needed."
        ),
        "infostealer": (
            "<b>Malware Family Detected:</b> Info Stealer<br/><br/>"
            "<b>Prevention:</b><br/>"
            "• Avoid storing passwords in browsers.<br/>"
            "• Use a secure, encrypted password manager.<br/><br/>"
            "<b>Response:</b><br/>"
            "• Monitor activity on affected accounts (email, banking, etc.).<br/>"
            "• Change credentials for all compromised services.<br/>"
            "• Notify relevant service providers of the incident."
        ),
        "worm": (
            "<b>Malware Family Detected:</b> Worm<br/><br/>"
            "<b>Prevention:</b><br/>"
            "• Enable firewalls and disable unnecessary file sharing.<br/>"
            "• Patch vulnerabilities immediately.<br/><br/>"
            "<b>Response:</b><br/>"
            "• Disconnect affected systems from the network.<br/>"
            "• Run antivirus scans across the environment.<br/>"
            "• Clean all connected removable devices (USB drives, external HDDs)."
        ),
    }

    family_key = family.lower().strip()
    matched_key = next((key for key in guidance_map if key in family_key), None)
    
    if matched_key:
        elements.append(Spacer(1, 1*cm))
        elements.append(Paragraph("Mitigation & Response Guidance", style_h2))
        elements.append(Paragraph(guidance_map[matched_key], style_body))


def generate_pdf(report_data, analysis_data, jenis, family, confidence):
    """Fungsi utama untuk menghasilkan file PDF."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    pdf_path = os.path.join(REPORT_DIR, f"report_{timestamp}.pdf")

    # Inisialisasi Dokumen dengan margin
    doc = SimpleDocTemplate(pdf_path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)

    # Menyiapkan Stylesheet
    styles = getSampleStyleSheet()
    style_h1 = ParagraphStyle("H1", parent=styles["h1"], fontName="Helvetica-Bold", fontSize=18,
                              textColor=COLOR_PRIMARY_DARK, spaceAfter=12, alignment=TA_LEFT)
    style_h2 = ParagraphStyle("H2", parent=styles["h2"], fontName="Helvetica-Bold", fontSize=14,
                              textColor=COLOR_PRIMARY_DARK, spaceAfter=10, spaceBefore=12, alignment=TA_LEFT)
    style_body = ParagraphStyle("Body", parent=styles["Normal"], fontName="Helvetica", fontSize=10,
                                textColor=COLOR_TEXT, alignment=TA_LEFT, leading=14)
    style_table_cell = ParagraphStyle("TableCell", parent=style_body, fontSize=9)
    style_table_header = ParagraphStyle("TableHeader", parent=style_table_cell, fontName="Helvetica-Bold", textColor=colors.white)
    style_paragraph = ParagraphStyle("SummaryParagraph", parent=style_body, fontSize=10, leading=14, spaceAfter=8, alignment=TA_JUSTIFY)
    elements = []
    
    # Menambahkan template header/footer
    doc.addPageTemplates([ReportPDFTemplate('main', doc)])

    # --- Bagian Ringkasan ---
    elements.append(Paragraph("Analysis Summary", style_h2))
    
    target = analysis_data.get("target", {})
    submitted = analysis_data.get("submitted", {})
    tasks = analysis_data.get("tasks", [])
    task = tasks[0] if tasks else {}
    analysis_id = analysis_data.get("id", "-")
    score = read_cvss_score()
    severity = get_cvss_severity(score)

    style_table_cell_white = ParagraphStyle("TableCellWhite", parent=style_table_cell, textColor=colors.white)
    summary_data = [
        [Paragraph("<b>Analysis ID</b>", style_table_cell_white), Paragraph(analysis_id, style_table_cell)],
        [Paragraph("<b>File Name</b>", style_table_cell_white), Paragraph(target.get("filename", "-"), style_table_cell)],
        [Paragraph("<b>File Size</b>", style_table_cell_white), Paragraph(str(target.get("size", "-")), style_table_cell)],
        [Paragraph("<b>MD5</b>", style_table_cell_white), Paragraph(submitted.get("md5", "-"), style_table_cell)],
        [Paragraph("<b>SHA256</b>", style_table_cell_white), Paragraph(submitted.get("sha256", "-"), style_table_cell)],
        [Paragraph("<b>Start Time</b>", style_table_cell_white), Paragraph(format_timestamp(task.get("started_on", {}).get("__isodt__", "-")), style_table_cell)],
        [Paragraph("<b>End Time</b>", style_table_cell_white), Paragraph(format_timestamp(task.get("stopped_on", {}).get("__isodt__", "-")), style_table_cell)],
        [Paragraph("<b>Severity Score</b>", style_table_cell_white), Paragraph(f"{score} ({severity})", style_table_cell)],
        [Paragraph("<b>Classification</b>", style_table_cell_white), Paragraph(f"<b>{jenis}</b> (Malware Probability: {confidence})", style_table_cell)],
        [Paragraph("<b>Malware Family</b>", style_table_cell_white), Paragraph(family, style_table_cell)],
    ]
    
    summary_table = LongTable(summary_data, colWidths=[3.5*cm, None])
    summary_table.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, COLOR_MEDIUM_GREY),
        ('BACKGROUND', (0, 0), (0, -1), COLOR_PRIMARY_DARK),  # Kolom kiri (label)
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),         # Teks kolom kiri
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),      # Bold teks kolom kiri
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 1*cm))

    # --- Bagian Signatures ---
    add_signature_table_with_narrative(report_data, elements, style_h2, style_table_cell, style_table_header)

    # --- Bagian Process Tree ---
    add_process_tree_table(report_data, elements, style_h2, style_table_cell, style_table_header)

    # --- Bagian MITRE TTP Table ---
    add_mitre_ttp_table(report_data, elements, style_h2, style_table_cell, style_table_header)

    # --- Bagian DNS Queries ---
    add_dns_query_table(report_data.get("network", {}), elements, style_h2, style_table_cell, style_table_header)

    # Tambahkan bagian UDP
    add_udp_table(report_data, elements, style_h2, style_table_cell, style_table_header)

    add_summary_section(report_data, elements, style_h2, style_paragraph)

    add_mitigation_guidance(family, elements, style_h2, style_body)



    # --- Glossary EN ---
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph("Glossary of Terms", style_h2))
    glossary_en = [
    ["Malware", "Malicious software designed to harm, exploit, or disrupt systems or data."],
    ["Benign", "A file or program that does not show harmful or suspicious behavior."],
    ["Malware Family", "A group of malware that share similar behavior, structure, or purpose."],
    ["Probability", "A measure of how confident the system is about its classification result (as Malware or Benign)."],
    ["Signature", "A rule or indicator that identifies a specific malicious behavior or pattern during execution."],
    ["Process", "An instance of a running program or executable observed during the malware's behavior."],
    ["Process Tree", "A hierarchical structure showing parent-child relationships of running processes."],
    ["Command Line", "The arguments used when executing a program, often providing insight into its behavior."],
    ["DNS Query", "A request made to resolve a domain name into an IP address, revealing possible C2 activity."],
    ["UDP Traffic", "Unreliable and connectionless communication used by malware for broadcasting or stealthy data transfer."],
    ["Multicast/Broadcast", "Network messages sent to multiple recipients, sometimes used for discovery or evasion."],
    ["MITRE ATT&CK", "A framework describing tactics and techniques used by threat actors, mapped from observed behavior."],
    ["TTP (Tactics, Techniques, Procedures)", "Specific adversary behaviors observed during execution and mapped to MITRE IDs."],
    ["CVSS Score", "Common Vulnerability Scoring System — a numerical value estimating the severity of a vulnerability or attack."],
    ["Severity Level", "The corresponding threat level based on the CVSS score (e.g., Low, Medium, Critical)."],
    ["Persistence Mechanism", "A method used by malware to maintain access, such as scheduled tasks or registry keys."],
    ["Registry Modification", "Changes made to the Windows registry, often to evade detection or maintain persistence."],
]

    glossary_data_en = [[Paragraph(term, style_table_cell), Paragraph(desc, style_table_cell)] for term, desc in glossary_en]
    glossary_table_en = create_styled_table(
        [[Paragraph("<b>Term</b>", style_table_header), Paragraph("<b>Definition</b>", style_table_header)]] + glossary_data_en,
        col_widths=[4*cm, None]
    )
    elements.append(glossary_table_en)
    elements.append(Spacer(1, 0.6*cm))
    elements.append(Paragraph(
        "<i>Note:</i> The CVSS score does not represent the overall danger of the malware, "
        "but rather the severity of the behavior observed.",
        style_body
    ))

    # --- Glosarium ID ---
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph("Glosarium Istilah", style_h2))
    glossary_id = [
    ["Malware", "Perangkat lunak jahat yang dirancang untuk merusak, mengeksploitasi, atau mengganggu sistem atau data."],
    ["Benign", "File atau program yang tidak menunjukkan perilaku berbahaya atau mencurigakan."],
    ["Malware Family", "Kelompok malware dengan perilaku, struktur, atau tujuan yang serupa."],
    ["Probabilitas", "Tingkat keyakinan sistem terhadap hasil klasifikasinya (misalnya sebagai Malware atau Benign)."],
    ["Signature", "Aturan atau indikator yang mendeteksi pola perilaku jahat tertentu saat eksekusi."],
    ["Process", "Proses program yang sedang berjalan yang diamati selama perilaku malware dianalisis."],
    ["Process Tree", "Struktur hierarki yang menunjukkan hubungan induk-anak antar proses selama eksekusi."],
    ["Command Line", "Argumen perintah saat menjalankan program, yang dapat mengungkapkan tujuannya."],
    ["DNS Query", "Permintaan untuk menerjemahkan nama domain menjadi alamat IP, bisa menunjukkan komunikasi C2."],
    ["UDP Traffic", "Komunikasi jaringan yang tidak memiliki koneksi tetap, sering digunakan untuk siaran atau komunikasi rahasia."],
    ["Multicast/Broadcast", "Pengiriman pesan jaringan ke banyak penerima, kadang digunakan untuk eksplorasi atau pengelabuan."],
    ["MITRE ATT&CK", "Kerangka kerja yang mendeskripsikan taktik dan teknik penyerang berdasarkan perilaku yang teramati."],
    ["TTP (Taktik, Teknik, Prosedur)", "Perilaku khas penyerang yang dipetakan dari aktivitas malware dan dikaitkan ke MITRE."],
    ["CVSS Score", "Nilai standar untuk mengukur tingkat keparahan kerentanan atau serangan tertentu."],
    ["Severity Level", "Level keparahan risiko berdasarkan skor CVSS (mis. Rendah, Sedang, Kritis)."],
    ["Persistence Mechanism", "Metode yang digunakan malware untuk bertahan hidup seperti task terjadwal atau pengubahan registry."],
    ["Registry Modification", "Perubahan pada sistem registry Windows untuk menghindari deteksi atau menanamkan persistensi."],
]
    glossary_data_id = [[Paragraph(term, style_table_cell), Paragraph(desc, style_table_cell)] for term, desc in glossary_id]
    glossary_table_id = create_styled_table(
        [[Paragraph("<b>Istilah</b>", style_table_header), Paragraph("<b>Definisi</b>", style_table_header)]] + glossary_data_id,
        col_widths=[4*cm, None]
    )
    elements.append(glossary_table_id)

    # --- Catatan CVSS ---
    elements.append(Spacer(1, 0.6*cm))
    elements.append(Paragraph(
        "<i>Catatan:</i> Skor CVSS tidak menunjukkan tingkat bahaya total dari malware, "
        "melainkan tingkat keparahan dari perilaku yang terdeteksi.",
        style_body
    ))


    # Build PDF
    try:
        doc.build(elements)
        logging.info(f"✅ PDF berhasil disimpan: {pdf_path}")
    except Exception as e:
        logging.error(f"❌ Gagal membuat PDF: {e}")

def main():
    """Fungsi utama untuk menjalankan skrip."""
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    result = find_latest_analysis()
    if not result:
        logging.error("❌ Tidak ada laporan analisis Cuckoo yang ditemukan. Pastikan path ANALYSIS_DIR sudah benar.")
        return

    report_path, analysis_path = result
    logging.info(f"Menggunakan laporan dari: {report_path}")
    
    try:
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        with open(analysis_path, 'r') as f:
            analysis_data = json.load(f)
    except json.JSONDecodeError as e:
        logging.error(f"❌ Gagal mem-parsing file JSON: {e}. File mungkin korup atau tidak lengkap.")
        return
    except Exception as e:
        logging.error(f"❌ Gagal membaca file laporan: {e}")
        return

    jenis, family, confidence = read_ml_results()
    generate_pdf(report_data, analysis_data, jenis, family, confidence)

if __name__ == "__main__":
    main()
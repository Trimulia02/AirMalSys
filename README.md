# 🛡️ AirMalSys

<div align="center">

[![Status](https://img.shields.io/badge/Status-Completed-green?style=flat-square)](https://github.com)
[![Python](https://img.shields.io/badge/Python-3.10-blue?style=flat-square&logo=python)](https://python.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-E95420?style=flat-square&logo=ubuntu)](https://ubuntu.com)
[![ML](https://img.shields.io/badge/ML-BiLSTM-purple?style=flat-square)](https://pytorch.org)

**Machine Learning-Based Malware Analysis System for Air-Gapped Environments**

</div>

---

<div align="center">

👨‍💻 **Creators**

<table>
<tbody>
<tr>
<td align="center" width="33%">
  <a href="https://github.com/Trimulia02">
    <img src="https://github.com/Trimulia02.png" width="90px;" style="border-radius:50%;" alt="Tri Mulia Bahar"/>
    <br /><sub><b>Tri Mulia Bahar</b></sub>
  </a><br /><sub>1103210103</sub>
</td>
<td align="center" width="33%">
  <a href="https://github.com/atanasiusps">
    <img src="https://github.com/atanasiusps.png" width="90px;" style="border-radius:50%;" alt="Atanasius Pradiptha Sampurno"/>
    <br /><sub><b>Atanasius Pradiptha S.</b></sub>
  </a><br /><sub>1103213036</sub>
</td>
<td align="center" width="33%">
  <a href="https://github.com/Kinnaruo">
    <img src="https://github.com/Kinnaruo.png" width="90px;" style="border-radius:50%;" alt="Kinanti Aria Widaswara"/>
    <br /><sub><b>Kinanti Aria Widaswara</b></sub>
  </a><br /><sub>1103213165</sub>
</td>
</tr>
</tbody>
</table>

**S1 Teknik Komputer | Universitas Telkom (2025)**

</div>

---

## 📋 Overview

AirMalSys is an automated malware analysis solution designed for air-gapped mini-PCs. It integrates **Cuckoo Sandbox 3** for isolated dynamic analysis and a **Bi-LSTM** model to classify malware behaviors with high accuracy.

---

## 🎬 Demo Video

<div align="center">

[![Watch Demo Video](https://img.youtube.com/vi/6Kd1kNdGdlw/maxresdefault.jpg)](https://youtu.be/6Kd1kNdGdlw?si=LejiTV_83X1l10FY)

**Click to watch on YouTube →**

</div>

---

## 📚 Buku Panduan

<div align="center">

[![Buku Panduan](https://img.shields.io/badge/📖%20Buku%20Panduan%20Sistem%20Analisis%20Malware-Download%20PDF-blue?style=for-the-badge)](Buku%20Panduan%20Sistem%20Analisis%20Malware.pdf)

</div>

---

## ✨ Performance Metrics

| Metrik | Nilai |
|---|---|
| Binary Classification (Malware vs. Benign) | **93% Accuracy** |
| Multiclass Classification (Cryptominer, Ransomware, Trojan) | **80% Accuracy** |
| Dataset | **2.476 sampel** (BODMAS & MalwareBazaar) |
| Kecepatan Analisis | **2–3 menit** per siklus |

---

## 🚀 Key Features

- **Air-Gapped Security** — Eksekusi aman via QEMU Windows 10 VM tanpa koneksi eksternal.
- **Intelligent Analysis** — Model Bi-LSTM menganalisis system calls, DNS, dan log jaringan.
- **Automated CVSS 4.0** — Penilaian kerentanan secara real-time.
- **Desktop GUI** — Antarmuka drag-and-drop berbasis PyQt5 (tanpa CLI).
- **Automated PDF Reports** — Laporan digenerate otomatis via ReportLab.

---

## 🛠️ Tech Stack

| Layer | Komponen |
|---|---|
| **OS** | Linux Ubuntu 22.04 LTS *(Strict requirement)* |
| **Core** | Python 3.10, Cuckoo3, QEMU, VMCloak |
| **ML** | PyTorch, Scikit-learn, NumPy, Pandas |
| **Services** | uWSGI, Nginx, PyQt5 |

---

## ⚙️ Quick Start

1. **Prepare Environment** — Pastikan Ubuntu 22.04 dan user `cuckoo` (non-sudo) tersedia.
2. **Setup Sandbox** — Install Cuckoo3 dan inisialisasi VMCloak Windows 10 VM.
3. **Run** — Jalankan shortcut aplikasi; sistem mengonfigurasi QEMU bridge dan daemon secara otomatis.
4. **Analyze** — Drag & drop file `.exe` untuk memulai pipeline analisis.

---

## ⚠️ Limitations

- Hanya mendukung **Ubuntu 22.04**.
- Performa bergantung pada keberhasilan `report.json` dari sandbox engine.
- Model bersifat statis; memerlukan retraining manual untuk ancaman zero-day baru.

---

## 📄 Citation

```text
Bahar, T.M., Sampurno, A.P., Widaswara, K.A. (2025).
"Machine Learning-Based Malware Analysis System in Air-Gap Environment Using Mini-PC".
Capstone Design Thesis, Computer Engineering, Universitas Telkom.
```

# Cuckoo3 Sandbox – Air-Gapped Malware Analysis

---

***Creators** :
1. Tri Mulia Bahar (github.com/Trimulia02)
2. Atanasius Pradiptha Sampurno (github.com/atanasiusps)
3. Kinanti Aria Widaswara (github.com/Kinnaruo)

---

## Overview
This project integrates **Cuckoo Sandbox 3** into an **air-gapped malware analysis system** running on a **mini-PC**.  
It allows safe dynamic analysis of malware inside isolated Windows VMs without internet access, eliminating cloud costs and minimizing security risks. 

This project was built for a college final project task. For that reason, all development has been stopped, as the creators have already graduated. 

---

## Features
- **Air-Gapped Security** – No internet connection, preventing malware leaks.
- **Automated Initialization** – Shell scripts configure networking, cleanup, and sandbox startup.
- **Windows VM Analysis** – Powered by QEMU + VMCloak.
- **Web-Based File Upload** – Simple interface for submitting samples without CLI.
- **Automated Reporting** – Generates detailed `report.json` and optional PDF summaries.
- **White-Box Tested** – Verified main logic paths for stability.

---

## Requirements
- **OS**: Ubuntu 22.04
- **Python**: 3.10
- **Linux User**: Must have a user named `cuckoo`
- **Dependencies**: Refer to [Cuckoo3 official documentation](https://github.com/cert-ee/cuckoo3)
- **Tools**: QEMU, VMCloak, YARA, uWSGI, Nginx, and all official Cuckoo3 dependencies

---

## Installation and Usage
1. Ensure you are using the cuckoo Linux user.
   - sudo adduser cuckoo
   
3. **Follow the official Cuckoo3 installation guide**  
   - [Cuckoo3 Documentation](https://github.com/cert-ee/cuckoo3)
   - Ensure all dependencies are installed.

4. **Clone this repository**

5. As per last development, **this system can only be used via terminal.**
  # From home
  cd TA_AnalisisMalware/Cuckooupload

  # From TA_AnalisisMalware/Cuckooupload
  python3 main.py




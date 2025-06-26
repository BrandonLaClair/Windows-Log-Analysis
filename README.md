# Windows Log Analysis Tool

A Python-based GUI tool to parse and analyze `.evtx` Windows Event Log files for suspicious activity. Built to assist SOC analysts, blue teamers, and security-minded users in rapidly triaging logs and detecting signs of compromise.

---

## Features

- Parses `.evtx` Windows Event Logs
- Filters logs by **Event ID** and **Computer Name**
- Displays matched alerts with timestamps and context
- Real-time terminal output + GUI-based results pane
- Exports filtered results to JSON
- Mdular front-end/back-end separation


## Example Pictures
![Windows Log Analysis Screenshot](assets/Example4624.png)
![Windows Log Analysis Screenshot](assets/ExampleParsing.png)
![Windows Log Analysis Screenshot](assets/ExampleWin11.png)


## Why This Matters

Windows event logs are critical for defenders, whether you’re working in a SOC, doing internal IT support, or securing your own home machine. This tool enables quick identification of:

- Failed logon attempts (Event ID: 4625)
- Successful logons (Event ID: 4624)
- Special privileges assigned (Event ID: 4672)
- Process creation (Event ID: 4688)
- Audit log cleared (Event ID: 1102)
- PowerShell script execution (Event ID: 4104)


## Tech Stack

- Python 3.11+
- `tkinter` (GUI)
- `python-evtx` (EVTX parser)
- `xmltodict` (XML handling)
- Visual Studio Code (IDE)
- Windows 11 VM for generating test logs


##  Installation Process

```bash
git clone https://github.com/BrandonLaClair/Windows-Log-Analysis.git
cd Windows-Log-Analysis
pip install -r requirements.txt
python gui.py



## How to Use
- Launch the tool with python gui.py
- Click Select File and choose a .evtx log file
- Choose an Event ID or Computer Name to filter
- Click Run Analysis
- View results in the GUI and download the report if needed



## Planned Enhancements
- Dynamically populate Computer Name filter
- Support multiple .evtx files at once
- Add date range filtering
- Highlight suspicious events (color-coded)
- Export to .csv or .html
- Theme toggle (light/dark mode)
- Store analysis sessions locally for quicker parsing and filtering, without having to re-scan
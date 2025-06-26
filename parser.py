import xmltodict
from Evtx.Evtx import Evtx

def parse_evtx(file_path, selected_event_id="All", selected_computer="All", output_callback=None):
    parsed_events = []
    total_parsed = 0

    try:
        with Evtx(file_path) as log:
            records = list(log.records())[-5000:]  # Last 5000 records

            selected_id_number = selected_event_id.split(" - ")[0] if selected_event_id != "All" else None
            selected_computer_name = selected_computer if selected_computer != "All" else None

            for i, record in enumerate(records):
                try:
                    event_dict = xmltodict.parse(record.xml())
                    system_data = event_dict.get("Event", {}).get("System", {})
                    event_data = event_dict.get("Event", {}).get("EventData", {})

                    raw_event_id = system_data.get("EventID", None)
                    event_id = raw_event_id.get("#text") if isinstance(raw_event_id, dict) else raw_event_id
                    if event_id:
                        event_id = str(event_id)
                    else:
                        continue

                    if selected_id_number and event_id != selected_id_number:
                        continue

                    computer_name = system_data.get("Computer", "Unknown")

                    if selected_computer_name and selected_computer_name != computer_name:
                        continue

                    timestamp = system_data.get("TimeCreated", {}).get("@SystemTime", "Unknown")
                    description = {
                        "4624": "Successful Logon",
                        "4625": "Failed Logon",
                        "4672": "Special Privileges Assigned",
                        "4688": "Process Creation",
                        "1102": "Audit Log Cleared",
                        "4104": "PowerShell Execution"
                    }.get(event_id, "Unknown Event")

                    parsed_events.append({
                        "EventID": event_id,
                        "Description": description,
                        "Computer": computer_name,
                        "TimeCreated": timestamp
                    })

                except Exception as e:
                    if output_callback:
                        output_callback(f"[!] Failed to parse record: {str(e)}\n")

                total_parsed += 1
                if total_parsed % 1000 == 0 and output_callback:
                    output_callback(f"[+] Processed {total_parsed}/{len(records)} records...\n")

    except Exception as e:
        if output_callback:
            output_callback(f"[!] Error opening .evtx file: {str(e)}\n")
        return []

    return parsed_events

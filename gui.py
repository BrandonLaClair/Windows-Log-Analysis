import tkinter as tk
from tkinter import filedialog, messagebox
import json
from parser import parse_evtx
import threading  

selected_file = None
parsed_alerts = None

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename(
        title="Select an EVTX file",
        filetypes=[("EVTX files", "*.evtx")]
    )
    if selected_file:
        terminal_output.insert("end", f"[+] File selected: {selected_file}\n")
        terminal_output.see("end")


def run_analysis():
    if not selected_file:
        messagebox.showwarning("No File", "Please select a file first.")
        return

    terminal_output.insert(tk.END, "[*] Starting analysis...\n")
    terminal_output.see(tk.END)

    def stream_output(msg):
        terminal_output.insert("end", msg)
        terminal_output.see("end")

    def background_task():
        global parsed_alerts
        selected_event = event_id_var.get()
        selected_computer_name = computer_var.get()

        parsed_output.delete("1.0", "end")

        parsed_alerts = parse_evtx(
            file_path=selected_file,
            selected_event_id=selected_event,
            selected_computer=selected_computer_name,
            output_callback=stream_output
        )

        if not parsed_alerts:
            terminal_output.insert(tk.END, "[!] No matching events found.\n")
            parsed_output.insert("end", "No matching events found.\n")
        else:
            terminal_output.insert(tk.END, f"[+] Analysis complete. {len(parsed_alerts)} matching events found.\n")
            for alert in parsed_alerts:
                parsed_output.insert("end", f"[{alert['EventID']}] {alert['Description']} - {alert['TimeCreated']} on {alert['Computer']}\n")

        terminal_output.see(tk.END)
        parsed_output.see(tk.END)

 
    threading.Thread(target=background_task).start()


def clear_results():
    global parsed_alerts, all_alerts, selected_file
    parsed_alerts = []
    all_alerts = []
    selected_file = None
    parsed_output.delete("1.0", "end")
    terminal_output.delete("1.0", "end")
    terminal_output.insert("end", "[*] File deselected.\n")


def download_report():
    if not parsed_alerts:
        messagebox.showinfo("Nothing to Save", "Run an analysis before downloading.")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON files", "*.json")],
        title="Save Report As"
    )
    if file_path:
        with open(file_path, "w") as f:
            json.dump(parsed_alerts, f, indent=4)
        messagebox.showinfo("Saved", f"Report saved to:\n{file_path}")

root = tk.Tk()
root.title("Windows Log Analysis")
root.geometry("1100x600")
root.minsize(1100, 600)
root.config(background="#1e1e1e")

filter_bar = tk.Frame(root, bg="#d9d9d9", height=40)
filter_bar.pack(fill="x", padx=10, pady=(0, 5))

tk.Label(filter_bar, text="Win EVTX", bg="#d9d9d9", fg="black", font=("Segoe UI", 12, "bold")).pack(side="left", padx=(0, 20))

tk.Label(filter_bar, text="Filter Event ID:", bg="#d9d9d9", fg="black", font=("Segoe UI", 10)).pack(side="left")

event_id_var = tk.StringVar()
event_id_options = [
    "All",
    "4624 - Successful Logon",
    "4625 - Failed Logon",
    "4672 - Special Privileges Assigned",
    "4688 - Process Creation",
    "1102 - Audit Log Cleared",
    "4104 - PowerShell Execution"
]
event_id_var.set("All")
tk.OptionMenu(filter_bar, event_id_var, *event_id_options).pack(side="left", padx=(5, 50))

computer_var = tk.StringVar()
computer_options = ["All"]
computer_var.set("All")

computer_dropdown = tk.OptionMenu(filter_bar, computer_var, *computer_options)
computer_dropdown.pack(side="right", padx=(10, 0))

computer_label = tk.Label(
    filter_bar,
    text="Computer:",
    bg="#d9d9d9",
    fg="black",
    font=("Segoe UI", 10)
)
computer_label.pack(side="right")


main_frame = tk.Frame(root, bg="#f0f0f0")
main_frame.pack(fill="both", expand=True)

output_section = tk.Frame(main_frame, bg="#f0f0f0")
output_section.pack(fill="both", expand=True, padx=20, pady=(10, 0))

parsed_output = tk.Text(
    output_section, wrap="word", bg="#222222", fg="white",
    font=("Segoe UI", 10), relief="sunken", bd=1, height=20
)
parsed_output.pack(fill="both", expand=True, side="top")

tk.Frame(output_section, height=2, bg="#a0a0a0").pack(fill="x", pady=5)

terminal_output = tk.Text(
    output_section, wrap="word", bg="#222222", fg="white",
    font=("Consolas", 10), relief="sunken", bd=1, height=5
)
terminal_output.pack(fill="x", side="bottom")

tk.Button(
    main_frame, text="Download Report",
    font=("Segoe UI", 9), width=20,
    command=download_report
).pack(pady=(0, 5))

bottom_bar = tk.Frame(main_frame, bg="#f0f0f0", height=40)
bottom_bar.pack(side="bottom", fill="x", pady=(5, 10), padx=20)

btn_style = {
    "font": ("Segoe UI", 9),
    "width": 18
}

tk.Button(bottom_bar, text="Select File", command=select_file, **btn_style).pack(side="left", expand=True)
tk.Button(bottom_bar, text="Run Analysis", command=run_analysis, **btn_style).pack(side="left", expand=True)
tk.Button(bottom_bar, text="Clear Results", command=clear_results, **btn_style).pack(side="left", expand=True)

root.mainloop()

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from concurrent.futures import ThreadPoolExecutor
from vt_utils import check_ip_reputation, check_url_reputation, check_hash_reputation
from app_utils import choose_file, save_data, log_event

root = tk.Tk()
root.title("VirusTotal Checker")
root.geometry("660x800")
root.configure(bg="#1E1E1E")

headers_map = {
    "IP": ["ip", "reputation", "country", "detection_ratio", "vt_link"],
    "URL": ["url", "reputation", "detection_ratio", "vt_link"],
    "MD5 Hash": ["hash", "malicious_detections", "detection_ratio", "vt_link"],
    "SHA1 Hash": ["hash", "malicious_detections", "detection_ratio", "vt_link"],
    "SHA256 Hash": ["hash", "malicious_detections", "detection_ratio", "vt_link"],
}

executor = ThreadPoolExecutor(max_workers=5)

# Variables
direct_input_var = tk.StringVar()
output_filename_var = tk.StringVar()
check_type_var = tk.StringVar(value="IP")
input_selection_var = tk.StringVar(value="Direct Input")
output_format_var = tk.StringVar(value="CSV")

# The "Check" button
def check():
    data_type = check_type_var.get()
    if input_selection_var.get() == "Direct Input":
        input_data = direct_input_scrolled_text.get("1.0", "end-1c").splitlines()
    else:
        with open(file_input_entry.get(), 'r') as file:
            input_data = file.readlines()

    if not input_data:
        messagebox.showerror("Error", "No data to process.")
        return

    future_to_data = {executor.submit(check_data, data.strip(), data_type): data.strip() for data in input_data if data.strip()}

    results = []
    progress_bar["maximum"] = len(future_to_data)
    progress = 0

    for future in future_to_data:
        try:
            result = future.result()
            results.append(result)
            log_event(f"Processed {data_type} - {future_to_data[future]}", logs_scrolled_text)
        except Exception as exc:
            log_event(f"Error processing {future_to_data[future]}: {exc}", logs_scrolled_text)
        progress += 1
        progress_bar["value"] = progress
        root.update_idletasks()

    headers = headers_map[data_type]
    output_format = output_format_var.get()
    output_filename = file_output_entry.get()
    save_data(output_filename, results, output_format, headers)
    messagebox.showinfo("Information", "Data saved successfully!")

def check_data(data, data_type):
    if data_type == "IP":
        return check_ip_reputation(data)
    elif data_type == "URL":
        return check_url_reputation(data)
    elif data_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        return check_hash_reputation(data)

# GUI
frame = ttk.Frame(root, padding="20", style="TFrame")
frame.pack(padx=10, pady=10, expand=True, fill="both")

style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background="#1E1E1E")
style.configure("TLabel", background="#1E1E1E", foreground="#FFFFFF", font=("Helvetica", 11))
style.configure("TButton", background="#007ACC", foreground="#FFFFFF", font=("Helvetica", 11), padding=6)
style.configure("TCombobox", font=("Helvetica", 11))
style.configure("TRadiobutton", background="#1E1E1E", foreground="#FFFFFF", font=("Helvetica", 11))


logo_label = ttk.Label(frame, text="VirusTotal Checker", style="TLabel", font=("Helvetica", 18, "bold"))
logo_label.grid(row=0, column=0, columnspan=3, pady=15)


ttk.Label(frame, text="Choose Type:", style="TLabel").grid(row=1, column=0, sticky="w", pady=5)
check_type_combo = ttk.Combobox(frame, textvariable=check_type_var, values=["IP", "URL", "MD5 Hash", "SHA1 Hash", "SHA256 Hash"], state="readonly")
check_type_combo.grid(row=1, column=1, pady=5, padx=10, sticky="ew")


ttk.Radiobutton(frame, text="Direct Input", variable=input_selection_var, value="Direct Input", style="TRadiobutton").grid(row=2, column=0, sticky="w", pady=5)
ttk.Radiobutton(frame, text="From File", variable=input_selection_var, value="From File", style="TRadiobutton").grid(row=2, column=1, pady=5, sticky="w")


ttk.Label(frame, text="Input File:", style="TLabel").grid(row=3, column=0, sticky="w", pady=5)
file_input_entry = ttk.Entry(frame, textvariable=direct_input_var, width=50)
file_input_entry.grid(row=3, column=1, pady=5, sticky="ew")
file_input_button = ttk.Button(frame, text="Choose File", command=lambda: choose_file(file_input_entry), style="TButton")
file_input_button.grid(row=3, column=2, pady=5, sticky="w")


ttk.Label(frame, text="Type or Paste your input:", style="TLabel").grid(row=4, column=0, sticky="w", pady=5)
direct_input_scrolled_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=8, font=("Helvetica", 11))
direct_input_scrolled_text.grid(row=5, column=0, columnspan=3, pady=5, padx=10, sticky="ew")


ttk.Label(frame, text="Output File:", style="TLabel").grid(row=6, column=0, sticky="w", pady=5)
file_output_entry = ttk.Entry(frame, textvariable=output_filename_var, width=50)
file_output_entry.grid(row=7, column=1, pady=5, sticky="ew")
file_output_button = ttk.Button(frame, text="Choose File", command=lambda: choose_file(file_output_entry), style="TButton")
file_output_button.grid(row=7, column=2, pady=5, sticky="w")


ttk.Label(frame, text="Output Format:", style="TLabel").grid(row=8, column=0, sticky="w", pady=5)
output_format_combo = ttk.Combobox(frame, textvariable=output_format_var, values=["CSV", "JSON", "TXT"], state="readonly")
output_format_combo.grid(row=8, column=1, pady=2, padx=10, sticky="ew")


progress_bar = ttk.Progressbar(frame, orient="horizontal", mode="determinate")
progress_bar.grid(row=9, column=0, columnspan=3, pady=10, padx=10, sticky="ew")


check_button = ttk.Button(frame, text="Check", command=check, style="TButton")
check_button.grid(row=10, column=0, pady=20)
reset_button = ttk.Button(frame, text="Reset", command=lambda: [direct_input_scrolled_text.delete(1.0, tk.END), logs_scrolled_text.delete(1.0, tk.END), progress_bar.config(value=0)], style="TButton")
reset_button.grid(row=10, column=1, pady=20, sticky="e")


ttk.Label(frame, text="Logs:", style="TLabel").grid(row=11, column=0, sticky="w", pady=5)
logs_scrolled_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=70, height=8, font=("Helvetica", 11), background="#333333", foreground="#FFFFFF")
logs_scrolled_text.grid(row=12, column=0, columnspan=3, pady=5, padx=10, sticky="ew")

root.mainloop()

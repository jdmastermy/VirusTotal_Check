import csv
import json
import datetime
import tkinter as tk
from tkinter import filedialog
from typing import List, Dict

def choose_file(entry_widget):
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_widget.delete(0, 'end')
        entry_widget.insert(0, file_path)

def log_event(message: str, widget=None):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_message = f"[{timestamp}] {message}"
    print(log_message)
    if widget:
        widget.insert(tk.END, log_message + "\n")
        widget.yview(tk.END)

def save_data(filename: str, data: List[Dict], format: str, headers: List[str] = None):
    if format == "CSV":
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
    elif format == "JSON":
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
    elif format == "TXT":
        with open(filename, 'w') as file:
            for item in data:
                file.write(str(item) + "\n")

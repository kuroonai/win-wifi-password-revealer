#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Wi-Fi Password Retriever
"""

import os
import sys
import subprocess
import re
import csv
import platform
from collections import OrderedDict
from datetime import datetime
import PySimpleGUI as sg
import threading

# Theme and styling
sg.theme('LightBlue2')  # Setting a modern theme

class WiFiPasswordRetriever:
    def __init__(self):
        self.passwords = {}
        self.pwds = []
        self.os_type = platform.system()
        self.retrieving = False
        self.scan_count = 0
        
    def get_wifi_passwords(self):
        """Retrieve Wi-Fi passwords based on the operating system"""
        if self.os_type == "Windows":
            return self._get_windows_wifi_passwords()
        elif self.os_type == "Darwin":  # macOS
            return self._get_macos_wifi_passwords()
        elif self.os_type == "Linux":
            return self._get_linux_wifi_passwords()
        else:
            return {"Error": f"Unsupported OS: {self.os_type}"}
    
    def _get_windows_wifi_passwords(self):
        """Retrieve Wi-Fi passwords on Windows"""
        passwords = {}
        
        # Get all Wi-Fi profiles
        try:
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], 
                                            universal_newlines=True, 
                                            stderr=subprocess.DEVNULL)
        except subprocess.SubprocessError:
            return {"Error": "Unable to retrieve Wi-Fi profiles"}
        
        # Extract SSIDs
        ssids = []
        for line in output.split('\n'):
            if ': ' in line and "All User Profile" in line:
                ssid = line.split(': ')[1].strip()
                ssids.append(ssid)
        
        # Get password for each SSID
        for ssid in ssids:
            if not ssid:
                continue
                
            try:
                # Try with and without quotes for SSIDs with special characters
                try:
                    cmd = ['netsh', 'wlan', 'show', 'profile', f'name={ssid}', 'key=clear']
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
                except subprocess.SubprocessError:
                    cmd = ['netsh', 'wlan', 'show', 'profile', f'name="{ssid}"', 'key=clear']
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
                
                # Check if it's enterprise authentication
                if 'Authentication' in output and 'WPA2-Enterprise' in output:
                    passwords[ssid] = 'Enterprise Authentication - Not Available'
                    continue
                
                # Extract password
                for line in output.split('\n'):
                    if 'Key Content' in line:
                        password = line.split(': ')[1].strip()
                        passwords[ssid] = password
                        break
                else:  # No password found
                    passwords[ssid] = 'No Password or Not Available'
                    
            except (subprocess.SubprocessError, IndexError):
                passwords[ssid] = 'Error Retrieving Password'
        
        return passwords
    
    def _get_macos_wifi_passwords(self):
        """Retrieve Wi-Fi passwords on macOS using security command"""
        passwords = {}
        
        try:
            # Get list of preferred networks
            airport_cmd = "/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport"
            if not os.path.exists(airport_cmd):
                airport_cmd = "/usr/sbin/airport"  # Fallback location
                
            # If airport command exists, use it to get SSIDs
            ssids = []
            try:
                output = subprocess.check_output([airport_cmd, "-s"], 
                                               universal_newlines=True, 
                                               stderr=subprocess.DEVNULL)
                                               
                # Extract SSIDs from scan
                for line in output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        ssid = line.strip().split()[0]
                        ssids.append(ssid)
            except (subprocess.SubprocessError, FileNotFoundError):
                # Fallback to listing preferred networks
                output = subprocess.check_output(["networksetup", "-listpreferredwirelessnetworks", "en0"], 
                                               universal_newlines=True,
                                               stderr=subprocess.DEVNULL)
                for line in output.split('\n')[1:]:  # Skip header
                    if line.strip():
                        ssids.append(line.strip())
            
            # Get password for each SSID using security command
            for ssid in ssids:
                if not ssid:
                    continue
                
                try:
                    cmd = ["security", "find-generic-password", "-l", f"{ssid}", "-g"]
                    output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.PIPE)
                    
                    # Extract password from output
                    password_match = re.search(r'password: "(.*)"', output)
                    if password_match:
                        passwords[ssid] = password_match.group(1)
                    else:
                        # Note: This requires user prompt on macOS for security reasons
                        passwords[ssid] = "Password access requires admin privileges" 
                        
                except subprocess.SubprocessError:
                    passwords[ssid] = "Not Available (Admin privileges required)"
        
        except Exception as e:
            passwords["Error"] = f"MacOS password retrieval error: {str(e)}"
            
        return passwords
    
    def _get_linux_wifi_passwords(self):
        """Retrieve Wi-Fi passwords on Linux systems"""
        passwords = {}
        
        # Check if NetworkManager is available
        if not os.path.exists("/etc/NetworkManager/system-connections/"):
            try:
                # Try using the wireless-tools package (iwlist)
                output = subprocess.check_output(["iwlist", "scanning"], 
                                              universal_newlines=True,
                                              stderr=subprocess.DEVNULL)
                                              
                # Extract SSIDs
                ssids = []
                for line in output.split('\n'):
                    if "ESSID:" in line:
                        ssid = line.split('ESSID:"')[1].split('"')[0]
                        if ssid:
                            ssids.append(ssid)
                
                for ssid in ssids:
                    passwords[ssid] = "Password stored in system keyring"
                
                return passwords
            except subprocess.SubprocessError:
                return {"Error": "Network information unavailable. Try running with sudo."}
        
        # Use NetworkManager - requires root
        try:
            # Get list of connections
            nm_files = os.listdir("/etc/NetworkManager/system-connections/")
            
            for file in nm_files:
                full_path = os.path.join("/etc/NetworkManager/system-connections/", file)
                try:
                    with open(full_path, 'r') as f:
                        content = f.read()
                        
                        # Extract SSID
                        ssid_match = re.search(r'ssid=(.*)', content)
                        if ssid_match:
                            ssid = ssid_match.group(1).strip()
                        else:
                            ssid = file.replace('.nmconnection', '')
                        
                        # Extract password
                        psk_match = re.search(r'psk=(.*)', content)
                        if psk_match:
                            password = psk_match.group(1).strip()
                            passwords[ssid] = password
                        else:
                            passwords[ssid] = "No Password or Enterprise Auth"
                            
                except (PermissionError, IOError):
                    # This will happen if not running as root
                    passwords[file.replace('.nmconnection', '')] = "Permission Denied (Run as root)"
                    
        except Exception as e:
            passwords["Error"] = f"Linux password retrieval error: {str(e)}"
            
        return passwords
    
    def start_retrieval(self, window):
        """Start password retrieval in a separate thread and update progress bar"""
        if self.retrieving:
            return
            
        self.retrieving = True
        
        def retrieve_thread():
            window["progress_bar"].update(visible=True)
            window["status"].update("Scanning Wi-Fi networks...")
            
            # Get passwords
            self.passwords = self.get_wifi_passwords()
            
            # Sort passwords
            self.passwords = OrderedDict(sorted(self.passwords.items()))
            self.pwds = [list(x) for x in self.passwords.items()]
            
            # Add row numbers
            for i, p in enumerate(self.pwds, 1):
                p.insert(0, str(i))
            
            # Update table
            window["table"].update(values=self.pwds)
            window["status"].update(f"Found {len(self.pwds)} Wi-Fi networks")
            window["progress_bar"].update(visible=False)
            window["refresh"].update(disabled=False)
            window["export_btn"].update(disabled=False)
            window["copy_btn"].update(disabled=False)
            self.retrieving = False
        
        # Start thread
        threading.Thread(target=retrieve_thread, daemon=True).start()
    
    def export_to_csv(self, filepath):
        """Export passwords to CSV file"""
        try:
            header = ['S.No.', 'SSID', 'Password']
            with open(filepath, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(header)
                writer.writerows(self.pwds)
            return True
        except Exception as e:
            return str(e)
    
    def export_to_txt(self, filepath):
        """Export passwords to text file"""
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write("Wi-Fi Password Report\n")
                file.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write(f"System: {platform.system()} {platform.release()}\n\n")
                file.write("=" * 60 + "\n")
                
                for pwd in self.pwds:
                    file.write(f"{pwd[0]}. {pwd[1]}: {pwd[2]}\n")
            return True
        except Exception as e:
            return str(e)
    
    def copy_to_clipboard(self, window, selected_rows):
        """Copy selected password entries to clipboard"""
        if not selected_rows:
            window["status"].update("No rows selected for copying")
            return
            
        try:
            import pyperclip
            
            # Prepare text
            text = ""
            for row in selected_rows:
                data = self.pwds[row]
                text += f"SSID: {data[1]}, Password: {data[2]}\n"
                
            # Copy to clipboard
            pyperclip.copy(text)
            window["status"].update(f"Copied {len(selected_rows)} entries to clipboard")
            
        except ImportError:
            window["status"].update("Error: pyperclip module not installed")
        except Exception as e:
            window["status"].update(f"Error copying to clipboard: {str(e)}")

def main():
    """Main function to run the application"""
    retriever = WiFiPasswordRetriever()
    
    # Define layout with additional features
    layout = [
        [sg.Text("Wi-Fi Password Retriever", font=("Helvetica", 16), justification="center", 
                expand_x=True, pad=(10, 10))],
        
        [sg.Button("Scan Networks", key="refresh", size=(15, 1)),
         sg.Button("Export CSV", key="export_btn", size=(15, 1), disabled=True),
         sg.Button("Export TXT", key="export_txt_btn", size=(15, 1), disabled=True),
         sg.Button("Copy Selected", key="copy_btn", size=(15, 1), disabled=True)],
        
        [sg.Table(values=[], key='table', headings=['S.No.', 'SSID', 'Password'],
                  display_row_numbers=False, justification='left',
                  auto_size_columns=True, font=('Helvetica', 12),
                  num_rows=20, enable_events=True,
                  expand_x=True, expand_y=True,
                  select_mode=sg.TABLE_SELECT_MODE_EXTENDED)],
                  
        [sg.Text("Status: Ready", key="status", size=(50, 1))],
        [sg.ProgressBar(100, orientation='h', size=(40, 20), key='progress_bar', visible=False, expand_x=True)],
        
        [sg.HorizontalSeparator()],
        
        [sg.Text("OS: " + platform.system() + " " + platform.release(), size=(35, 1)),
         sg.Button("Exit", key="-done-", size=(10, 1))]
    ]
    
    # Create window
    try:
        icon_path = 'logo.ico' if os.path.exists('logo.ico') else None
        window = sg.Window("Wi-Fi Password Retriever", layout, 
                        resizable=True, icon=icon_path, finalize=True,
                        size=(800, 600))
        window["table"].expand(True, True)
    except Exception as e:
        # Fallback without icon if there's an issue
        window = sg.Window("Wi-Fi Password Retriever", layout, 
                        resizable=True, finalize=True,
                        size=(800, 600))
    
    # Event loop
    while True:
        event, values = window.read(timeout=100)
        
        if event == sg.WIN_CLOSED or event == "-done-":
            break
            
        elif event == "refresh":
            window["refresh"].update(disabled=True)
            retriever.start_retrieval(window)
            
        elif event == "export_btn":
            # Get filename for saving
            filename = sg.popup_get_file("Save Wi-Fi passwords as CSV", 
                                        save_as=True, 
                                        file_types=(("CSV Files", "*.csv"),),
                                        default_extension=".csv",
                                        default_path=f"WiFi_Passwords_{datetime.now().strftime('%Y%m%d')}.csv")
            if filename:
                result = retriever.export_to_csv(filename)
                if result is True:
                    window["status"].update(f"Saved to {filename}")
                else:
                    window["status"].update(f"Error: {result}")
                    
        elif event == "export_txt_btn":
            # Get filename for saving
            filename = sg.popup_get_file("Save Wi-Fi passwords as text file", 
                                        save_as=True, 
                                        file_types=(("Text Files", "*.txt"),),
                                        default_extension=".txt",
                                        default_path=f"WiFi_Passwords_{datetime.now().strftime('%Y%m%d')}.txt")
            if filename:
                result = retriever.export_to_txt(filename)
                if result is True:
                    window["status"].update(f"Saved to {filename}")
                else:
                    window["status"].update(f"Error: {result}")
        
        elif event == "copy_btn":
            selected_rows = values["table"]
            retriever.copy_to_clipboard(window, selected_rows)
            
        elif event == "table" and values["table"]:
            # Enable copy button when rows are selected
            window["copy_btn"].update(disabled=False)
    
    window.close()

if __name__ == "__main__":
    main()

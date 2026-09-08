"""Helper to create a Windows desktop shortcut."""

import os
import subprocess

def create_shortcut():
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    shortcut_path = os.path.join(desktop, "SecureLock.lnk")
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_vbs = os.path.join(current_dir, "Run_Silent.vbs")

    ps_script = f"""
    $ws = New-Object -ComObject WScript.Shell
    $s = $ws.CreateShortcut('{shortcut_path}')
    $s.TargetPath = 'wscript.exe'
    $s.Arguments = '"{target_vbs}"'
    $s.WorkingDirectory = '{current_dir}'
    $s.Description = 'SecureLock - Windows Folder Locker'
    $s.Save()
    """
    subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], check=True)
    if os.path.exists(shortcut_path):
        print(f"Shortcut created successfully at: {shortcut_path}")
    else:
        print("Shortcut creation failed.")

if __name__ == "__main__":
    create_shortcut()

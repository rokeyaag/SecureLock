"""Automatic installer for SecureLock on Windows.
Installs SecureLock.exe to AppData/Local/Programs/SecureLock and adds clean Desktop & Start Menu shortcuts.
"""

import os
import shutil
import subprocess

def install():
    source_dir = os.path.dirname(os.path.abspath(__file__))
    exe_source = os.path.join(source_dir, "dist", "SecureLock.exe")

    if not os.path.isfile(exe_source):
        print(f"Error: Executable not found at {exe_source}")
        return False

    local_appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
    install_dir = os.path.join(local_appdata, "Programs", "SecureLock")
    os.makedirs(install_dir, exist_ok=True)

    exe_target = os.path.join(install_dir, "SecureLock.exe")
    print(f"Copying SecureLock.exe to: {exe_target}...")
    shutil.copy2(exe_source, exe_target)

    # Clean up old shortcuts first if any
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    desktop_shortcut = os.path.join(desktop, "SecureLock.lnk")
    if os.path.exists(desktop_shortcut):
        try:
            os.remove(desktop_shortcut)
        except OSError:
            pass

    roaming_appdata = os.environ.get("APPDATA", os.path.expanduser("~\\AppData\\Roaming"))
    start_menu = os.path.join(roaming_appdata, "Microsoft", "Windows", "Start Menu", "Programs")
    start_shortcut = os.path.join(start_menu, "SecureLock.lnk")
    if os.path.exists(start_shortcut):
        try:
            os.remove(start_shortcut)
        except OSError:
            pass

    ps_script = f"""
    $ws = New-Object -ComObject WScript.Shell

    # Desktop Shortcut - strictly no arguments
    $s1 = $ws.CreateShortcut('{desktop_shortcut}')
    $s1.TargetPath = '{exe_target}'
    $s1.Arguments = ''
    $s1.WorkingDirectory = '{install_dir}'
    $s1.Description = 'SecureLock - Windows Folder Locker & Vault'
    $s1.Save()

    # Start Menu Shortcut - strictly no arguments
    $s2 = $ws.CreateShortcut('{start_shortcut}')
    $s2.TargetPath = '{exe_target}'
    $s2.Arguments = ''
    $s2.WorkingDirectory = '{install_dir}'
    $s2.Description = 'SecureLock - Windows Folder Locker & Vault'
    $s2.Save()
    """
    subprocess.run(["powershell", "-NoProfile", "-Command", ps_script], check=True)

    print("\n========================================================")
    print("  [SUCCESS] SecureLock Installation Completed Successfully!")
    print(f"  Program Location: {exe_target}")
    print(f"  Desktop Shortcut: {desktop_shortcut}")
    print(f"  Start Menu Shortcut: {start_shortcut}")
    print("========================================================")
    return True

if __name__ == "__main__":
    install()

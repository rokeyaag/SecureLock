# 🔒 SecureLock - Windows Folder Locker & Vault (v3.0)

A powerful, modern folder locker and vault application for Windows. SecureLock delivers **Military-Grade AES-256-GCM Envelope Encryption**, instant **Quick Lock** capability, and complete **Email OTP & Emergency Key Password Recovery**.

---

## 🌟 Core Features

1. **🛡️ AES-256-GCM Envelope Encryption (Highest Security)**:
   - Each folder is encrypted using a random 256-bit Data Encryption Key (DEK).
   - The encryption key is protected using dual-slot key wrapping: Slot 1 wraps the key with your primary password, and Slot 2 wraps the key with an emergency recovery secret.
2. **🔑 Password Recovery & Reset (Email OTP & Offline Key)**:
   - Forgotten your password? Reset it in seconds using a time-limited 6-digit **Email OTP** or your unique **Backup Recovery Key** (`SLOCK-XXXX-XXXX-XXXX-XXXX`).
   - Zero-re-encryption technology: Your password is reset in milliseconds without re-encrypting massive gigabytes of files.
   - Offline emergency unlock: Unlock your files even without internet access or an active email server.
3. **⚡ Instant Quick Lock**:
   - Conceal and protect massive directories (e.g. 20–100 GB game directories or video media) in a single second using Windows CLSID and shell protection.
4. **🖥️ Modern Graphical User Interface**:
   - Sleek dark theme designed with high-contrast usability.
   - Password show/hide toggle (`👁️`).
   - Real-time password strength meter.
   - Single-click recovery key clipboard copy (`📋 Copy Code`).
   - Integrated 'Forgot Password?' modal with live OTP delivery.
   - Visual locked vaults table with status monitoring and Explorer integration.
5. **🚀 One-Click Launchers & Shortcuts**:
   - Desktop and Start Menu shortcuts.
   - Silent launcher (`Run_Silent.vbs`) and interactive batch launcher (`Run_SecureLock.bat`).

---

## 📂 Launching the Application

- Double-click the **`SecureLock`** shortcut on your **Desktop**.
- Or double-click [**`Run_Silent.vbs`**](file:///C:/Users/HP/.gemini/antigravity/scratch/FolderLocker/Run_Silent.vbs) or [**`Run_SecureLock.bat`**](file:///C:/Users/HP/.gemini/antigravity/scratch/FolderLocker/Run_SecureLock.bat) inside the project folder.

---

## 📖 How to Use

### 1. Locking a Folder:
1. Navigate to the **Lock Folder** tab.
2. Click `📁 Browse Folder...` and choose the target directory.
3. Select your security mode:
   - **AES-256 Envelope Encryption** (Recommended - Military Grade).
   - **Instant Quick Lock** (Fast lock for large media or games).
4. Enter and confirm your master password.
5. Save your **Backup Recovery Key** by clicking `📋 Copy Code` (Optional: enter your recovery email address for OTP delivery).
6. Click **`🔒 Lock Folder Now`**.

### 2. Unlocking a Folder:
1. Navigate to the **Unlock Folder** tab.
2. Click `📂 Browse Locked File...` and select your `.slock` vault file or quick-locked folder.
3. Enter your password and click **`🔓 Unlock & Restore Folder`**.
4. Once unlocked, click **`📂 Open Restored Folder in File Explorer`** to access your files immediately.

### 3. Forgot Password / Resetting Password:
1. On the **Unlock Folder** tab, select your locked container.
2. Click **`❓ Forgot Password? (Email OTP / Recovery Key)`**.
3. In the popup dialog:
   - Click **`📩 Send 6-Digit OTP`** to receive a verification code at your registered email address.
   - Enter the 6-digit OTP code (or paste your offline backup recovery key).
   - Type your desired new password and confirm it.
   - Click **`✅ Verify OTP & Reset Password`** to update your password immediately.

---

## ⚙️ Email OTP Setup (Optional)

1. Click the **`⚙️ Email Settings`** button in the top-right corner of SecureLock.
2. Enter your sender email (Gmail, Outlook, or custom SMTP server) and App Password.
   - *For Gmail*: Go to Google Account > Security > Enable 2-Step Verification > Create an "App Password" (16 characters) and paste it here.
3. Click **`🧪 Test Connection`** to verify delivery, then click **`💾 Save Settings`**.

---

## ⌨️ Command Line Interface (CLI Usage)

```bash
# Lock a folder with AES-256 encryption
python main.py lock "C:\Path\To\YourFolder" -p "YourPassword123"

# Reset password using recovery key
python main.py reset-password "C:\Path\To\YourFolder.slock" -r "SLOCK-XXXX-XXXX" -n "NewPassword456"

# Unlock directly using recovery key
python main.py unlock "C:\Path\To\YourFolder.slock" -r "SLOCK-XXXX-XXXX"
```

---

## 🛡️ Technical Architecture

- **Envelope Encryption**: AES-256-GCM (Authenticated Encryption with Associated Data).
- **Key Derivation**: PBKDF2 with HMAC-SHA256 and high iteration count.
- **Key Wrapping**: Dual-slot AES Key Wrap (RFC 3394 / RFC 5649).
- **Container Format**: Custom binary header with authenticated metadata, nonce, and integrity tag.
- **Cross-Platform Cryptography**: Powered by Python `cryptography` library.


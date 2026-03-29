# Finding Encrypted Files & Renaming the Extension

## 1. Where to find encrypted files

### Server (API) encrypted files

When you encrypt via the **API** (e.g. curl or the panels that call the server), files are written under the **`security-data`** folder next to the RawrZ Payload Builder app:

```
RawrZ Payload Builder/
├── security-data/
│   ├── processed/     ← encrypted outputs (e.g. calc.exe.enc)
│   ├── uploads/       ← uploaded originals (if you used multipart upload)
│   ├── keys/
│   └── logs/
```

**Full path on your machine:**

- **Processed (encrypted):**  
  `D:\BigDaddyG-Part4-RawrZ-Security-master\RawrZ Payload Builder\security-data\processed\`

**How to list them (PowerShell):**

```powershell
cd "D:\BigDaddyG-Part4-RawrZ-Security-master\RawrZ Payload Builder"
Get-ChildItem .\security-data\processed\
```

**How to list them (API):**

```powershell
curl -s http://127.0.0.1:3000/api/files/list
```

(Note: `/api/files/list` returns files in `uploads/`. Processed files are not listed by that endpoint; use the folder above or add a similar list endpoint for `processed/`.)

---

### Browser (Advanced Encryption Panel) encrypted files

When you encrypt in the **Advanced Encryption Panel** in the browser (AES-256-GCM/CBC, in-browser):

- The file is **downloaded** by the browser; it is **not** stored on the server.
- You choose where it’s saved (e.g. **Downloads**), and the default name is `&lt;originalname&gt;.encrypted` (e.g. `document.pdf.encrypted`).

So to “find” those: check your **browser’s download folder** (e.g. `%USERPROFILE%\Downloads`).

---

## 2. Can you rename `.enc` (or `.encrypted`) to another extension?

**Yes.** The extension is only a label. Decryption uses the **contents** of the file, not the filename.

### In-browser format (Advanced Encryption Panel)

- The file starts with a **4-byte magic**: `RZEF` (hex `52 5A 45 46`).
- Decryption checks these bytes. If they match, it reads salt, IV, and ciphertext from fixed positions and decrypts.
- So you can rename:
  - `file.encrypted` → `file.exe`, `file.pdf`, `file.dat`, `file.xyz`, or anything else.
- As long as you **don’t change the file contents**, it will still decrypt in the panel.  
  When you click **Decrypt File**, choose that renamed file; the panel will recognize it by the **RZEF** header, not by the extension.

### Server (API) format

- Server-encrypted files are written as raw **IV + auth tag + ciphertext** (or IV + ciphertext for CBC).
- There is no magic header; the layout is fixed. Decryption uses that layout and the correct key/algorithm.
- Renaming `calc.exe.enc` to e.g. `calc.exe` or `data.bin` does **not** change the bytes, so it does **not** break the format.  
  Any tool that decrypts using the same layout and key will work regardless of the file extension.

**Summary:** Rename `.enc` or `.encrypted` to any extension you want; decryption still works as long as the file contents are unchanged and you use the right tool/password/format.

---

## 3. Quick reference

| Question | Answer |
|----------|--------|
| Where are server-encrypted files? | `...\RawrZ Payload Builder\security-data\processed\` |
| Where are browser-encrypted files? | Your browser’s download folder (e.g. `%USERPROFILE%\Downloads`) |
| Does renaming .enc break decryption? | No. Decryption uses the file contents (and magic/format), not the extension. |
| How does the panel recognize an encrypted file? | By the **RZEF** magic bytes at the start (browser format). |

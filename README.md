# BeruVirusGuard

BeruVirusGuard is a multithreaded file scanner designed to detect files containing known virus signatures and optionally quarantine infected files. It uses C++17's `std::filesystem` for directory traversal and supports multithreading to improve scanning performance.

---

## 🚀 Features
- **Multithreaded scanning**: Utilizes available CPU cores for faster scans.
- **Virus signature detection**: Scans files for predefined signatures.
- **Quarantine option**: Moves infected files to a quarantine directory.
- **Permission error handling**: Skips directories/files with permission issues.
- **Customizable signature file**: Load virus signatures from a file or use default ones.

---

## 🛠️ Requirements
- C++17 compatible compiler (e.g., g++ 9.0+ or MSVC 2017+)
- CMake (optional but recommended for building)
- Windows, Linux, or macOS

---

## 📦 Installation & Build

### Using g++ (Direct Command)
```bash
# Compile the code
g++ main.cpp scanworker.cpp -o BeruVirusGuard

# Run the scanner
./BeruVirusGuard <directory_to_scan> [signature_file] [quarantine_flag]
```

### Using CMake (Recommended)
```bash
mkdir build && cd build
cmake ..
cmake --build .
./BeruVirusGuard <directory_to_scan> [signature_file] [quarantine_flag]
```

---

## 📝 Usage
```bash
BeruVirusGuard <directory_to_scan> [signature_file] [quarantine_flag]
```

### Arguments:
- `<directory_to_scan>`: (Required) Path of the directory you want to scan.
- `[signature_file]`: (Optional) Path to a text file containing virus signatures (one per line).
- `[quarantine_flag]`: (Optional) Use `Q` to enable quarantine of infected files.

### Examples:
```bash
# Scan a directory using default signatures
./BeruVirusGuard "C:/Users/revon/Documents"

# Scan with a custom signature file
./BeruVirusGuard "C:/Users/revon/Documents" "signatures.txt"

# Scan with quarantine enabled
./BeruVirusGuard "C:/Users/revon/Documents" "signatures.txt" Q
```

---

## 🔒 Quarantine Feature
When the quarantine flag `Q` is provided, infected files are moved to a `quarantine/` directory located in the same folder where the executable is run.

```bash
[Scan] infected_test.txt -> Infected!
[Quarantine] infected_test.txt moved to quarantine/
```

---

## 🧪 Testing Infection Detection
To test the scanner's detection capabilities, you can create a sample file containing a known signature:

```bash
echo "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" > test_infected.txt
./BeruVirusGuard "./"
```

Expected output:
```bash
[Scan] ./test_infected.txt -> Infected!
```

---

## 🧹 Handling Errors
- **Permission Denied**: Files/directories you don't have access to will be skipped, and a warning will be displayed.
- **Invalid Directory**: The scanner will exit if the provided directory does not exist.

Example:
```bash
[Warning] Error processing C:/ProtectedFolder: Permission denied.
```

---

## 📄 License
This project is licensed under the MIT License.

---

## 🤝 Contributions
Pull requests and suggestions are welcome! Feel free to fork the repo and contribute.

---

## 💻 Author
Developed by poweristsutsun (BeruVirusGuard Creator)

For questions or issues, please open an issue or contact me directly.

---

## 🔔 Disclaimer
This software is for educational purposes only. Always use responsibly.
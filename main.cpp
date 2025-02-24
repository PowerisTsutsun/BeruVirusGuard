#include "scanworker.h"
#include <iostream>
#include <string>

/*
 * Example usage:
 *   ./antivirus /path/to/scan optional_signatures.txt
 *
 * This console-based example scans the specified directory using
 * multiple threads, checks for known signatures, and can optionally
 * quarantine infected files to a "quarantine" folder.
 */

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <directory_to_scan> [signature_file] [quarantine_enabled]\n\n"
                  << "Examples:\n"
                  << "  " << argv[0] << " /home/user/documents\n"
                  << "  " << argv[0] << " /home/user/documents signatures.txt\n"
                  << "  " << argv[0] << " /home/user/documents signatures.txt Q\n"
                  << "If 'Q' is provided as the third argument, quarantine is enabled.\n"
                  << std::endl;
        return 1;
    }

    std::string directory = argv[1];
    std::string sigFile   = (argc >= 3) ? argv[2] : "";
    bool enableQuarantine = false;
    if (argc >= 4 && (std::string(argv[3]) == "Q" || std::string(argv[3]) == "q")) {
        enableQuarantine = true;
    }

    // Create a ScanWorker instance
    ScanWorker worker;
    worker.setDirectoryToScan(directory);
    worker.setSignatureFile(sigFile);
    worker.setEnableQuarantine(enableQuarantine);

    // Start scanning
    worker.startScan();

    std::cout << "[Main] To stop scanning early, press ENTER." << std::endl;

    // Non-blocking wait for user input:
    std::cin.get();

    // Stop scanning if still in progress
    worker.stopScan();

    // Let any scanning threads finish gracefully
    // (In this design, calling startScan() and then stopScan() in
    //  such a quick succession might keep the program from scanning
    //  the entire directory, but the user can wait if they want.)
    std::cout << "[Main] Exiting." << std::endl;
    return 0;
}
#ifndef SCANWORKER_H
#define SCANWORKER_H

#include <string>
#include <vector>
#include <atomic>

/*
 * The ScanWorker class is responsible for scanning directories, detecting files
 * that match known virus signatures, and optionally moving those files to a
 * quarantine folder.
 */

class ScanWorker {
public:
    // Configure the scan
    void setDirectoryToScan(const std::string& dir);
    void setSignatureFile(const std::string& file);
    void setEnableQuarantine(bool enable);

    // Perform the directory scan using multiple threads
    void startScan();

    // Signal to all threads that they should stop
    void stopScan();

private:
    // Load signatures from a file; if empty or not found, use defaults
    std::vector<std::string> loadSignatures(const std::string& signatureFile);

    // Checks if a given file is infected by any known signature
    bool isInfected(const std::string& filePath,
                    const std::vector<std::string>& virusSignatures);

    // Moves infected files to the specified quarantine folder
    bool quarantineFile(const std::string& filePath,
                        const std::string& quarantineDir);

    // A thread function that scans a subset of files
    void scanFiles(const std::vector<std::string>& files,
                   const std::vector<std::string>& virusSignatures,
                   const std::string& quarantineDir,
                   bool enableQuarantine,
                   std::atomic_bool& keepScanning);

private:
    std::string m_directoryToScan;
    std::string m_signatureFile;
    bool        m_enableQuarantine{false};
    std::atomic_bool m_keepScanning{true};
};

#endif // SCANWORKER_H
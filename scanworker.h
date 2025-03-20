#ifndef SCANWORKER_H
#define SCANWORKER_H

#include <string>
#include <vector>
#include <atomic>

class ScanWorker {
public:
    // Configuration setters
    void setDirectoryToScan(const std::string& dir);
    void setSignatureFile(const std::string& file);
    void setHashFile(const std::string& file);
    void setEnableQuarantine(bool enable);

    // Start and stop scanning
    void startScan();
    void stopScan();

    // Detection functions
    bool isInfectedBySignature(const std::string& filePath,
                               const std::vector<std::string>& virusSignatures);
    bool isInfectedByHash(const std::string& filePath,
                          const std::vector<std::string>& virusHashes);
    bool isInfected(const std::string& filePath,
                    const std::vector<std::string>& virusSignatures,
                    const std::vector<std::string>& virusHashes,
                    bool useBoth = false);

private:
    std::string m_directoryToScan;
    std::string m_signatureFile;
    std::string m_hashFile;
    bool m_enableQuarantine = false;
    std::atomic_bool m_keepScanning {false};

    // Result counters
    std::atomic<int> m_totalFilesScanned {0};
    std::atomic<int> m_totalInfected {0};
    std::atomic<int> m_totalQuarantined {0};

    // Helper functions
    std::vector<std::string> loadSignatures(const std::string& signatureFile);
    std::vector<std::string> loadVirusHashes();
    bool quarantineFile(const std::string& filePath, const std::string& quarantineDir);
    void scanFiles(const std::vector<std::string>& files,
                   const std::vector<std::string>& virusSignatures,
                   const std::vector<std::string>& virusHashes,
                   const std::string& quarantineDir,
                   bool enableQuarantine,
                   std::atomic_bool& keepScanning);
};

#endif // SCANWORKER_H

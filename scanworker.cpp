#include "scanworker.h"
#include "hashhelper.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <mutex>
#include <sstream>
#include <vector>

namespace fs = std::filesystem;

// Global mutex to protect console output from multiple threads
static std::mutex gLogMutex;

void ScanWorker::setDirectoryToScan(const std::string& dir) {
    m_directoryToScan = dir;
}

void ScanWorker::setSignatureFile(const std::string& file) {
    m_signatureFile = file;
}

void ScanWorker::setHashFile(const std::string& file) {
    m_hashFile = file;
}

void ScanWorker::setEnableQuarantine(bool enable) {
    m_enableQuarantine = enable;
}

void ScanWorker::startScan() {
    // Reset the flag and counters so scanning can proceed
    m_keepScanning = true;
    m_totalFilesScanned = 0;
    m_totalInfected = 0;
    m_totalQuarantined = 0;

    // Verify the directory
    if (m_directoryToScan.empty() || !fs::exists(m_directoryToScan) || !fs::is_directory(m_directoryToScan)) {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cerr << "[Error] Invalid directory: " << m_directoryToScan << std::endl;
        return;
    }

    // Load signatures and virus hashes from their respective text files (or defaults)
    auto signatures = loadSignatures(m_signatureFile);
    auto virusHashes = loadVirusHashes();

    // Gather files to scan
    std::vector<std::string> allFiles;
    try {
        auto it = fs::recursive_directory_iterator(m_directoryToScan, fs::directory_options::skip_permission_denied);
        auto end = fs::recursive_directory_iterator();

        while (it != end) {
            try {
                if (!m_keepScanning) {
                    std::lock_guard<std::mutex> lock(gLogMutex);
                    std::cout << "[Info] Scanning stopped early.\n";
                    return;
                }
                fs::path currentPath;
                try {
                    currentPath = it->path();
                } catch (...) {
                    currentPath = "[Unknown Path]";
                }
                if (fs::is_regular_file(currentPath)) {
                    allFiles.push_back(currentPath.string());
                }
                ++it;
            }
            catch (const fs::filesystem_error& e) {
                std::string problemPath;
                try {
                    problemPath = it->path().string();
                } catch (...) {
                    problemPath = "[Unknown Path]";
                }
                {
                    std::lock_guard<std::mutex> lock(gLogMutex);
                    std::cerr << "[Warning] Error processing " << problemPath << ": " << e.what() << std::endl;
                }
                try {
                    it.disable_recursion_pending();
                } catch (...) {
                    // Ignored for safety
                }
                ++it;
            }
        }
    }
    catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cerr << "[Error] Exception while scanning directory: " << e.what() << std::endl;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[Info] Total files found: " << allFiles.size() << std::endl;
    }

    // Determine number of threads to use
    unsigned int hardwareThreads = std::thread::hardware_concurrency();
    if (hardwareThreads == 0) {
        hardwareThreads = 2; // fallback
    }
    {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[Info] Using up to " << hardwareThreads << " threads.\n";
    }

    // Split files into chunks for multiple threads
    std::vector<std::thread> threads;
    threads.reserve(hardwareThreads);

    std::vector<std::vector<std::string>> fileChunks(hardwareThreads);
    size_t chunkSize = allFiles.size() / hardwareThreads;
    size_t startIdx = 0;
    for (unsigned int i = 0; i < hardwareThreads; ++i) {
        size_t endIdx = (i == hardwareThreads - 1) ? allFiles.size() : (startIdx + chunkSize);
        fileChunks[i] = std::vector<std::string>(allFiles.begin() + startIdx, allFiles.begin() + endIdx);
        startIdx = endIdx;
    }

    // Directory for quarantined files
    std::string quarantineDir = "quarantine";

    // Spawn worker threads
    for (unsigned int i = 0; i < hardwareThreads; ++i) {
        threads.emplace_back(
            &ScanWorker::scanFiles,
            this,
            std::cref(fileChunks[i]),
            std::cref(signatures),
            std::cref(virusHashes),
            std::cref(quarantineDir),
            m_enableQuarantine,
            std::ref(m_keepScanning)
        );
    }

    // Join all threads
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    // Print summary results
    {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[Info] Scan complete." << std::endl;
        std::cout << "Total files scanned: " << m_totalFilesScanned.load() << std::endl;
        std::cout << "Total infected files: " << m_totalInfected.load() << std::endl;
        if (m_enableQuarantine) {
            std::cout << "Total quarantined files: " << m_totalQuarantined.load() << std::endl;
        }
    }
}

void ScanWorker::stopScan() {
    m_keepScanning = false;
}

std::vector<std::string> ScanWorker::loadSignatures(const std::string& signatureFile) {
    std::vector<std::string> signatures;
    
    if (!signatureFile.empty()) {
        std::ifstream infile(signatureFile);
        if (infile.is_open()) {
            std::string line;
            while (std::getline(infile, line)) {
                if (!line.empty()) {
                    signatures.push_back(line);
                }
            }
            infile.close();

            if (!signatures.empty()) {
                std::lock_guard<std::mutex> lock(gLogMutex);
                std::cout << "[Info] Loaded " << signatures.size()
                          << " signatures from " << signatureFile << std::endl;
            }
        }
    }

    if (signatures.empty()) {
        signatures = {
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
            "MALWARE_SIGNATURE_EXAMPLE",
            "TROJAN_SAMPLE"
        };
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[Info] Using default signatures.\n";
    }

    return signatures;
}

std::vector<std::string> ScanWorker::loadVirusHashes() {
    std::vector<std::string> virusHashes;
    
    if (!m_hashFile.empty()) {
        std::ifstream infile(m_hashFile);
        if (infile.is_open()) {
            std::string line;
            while (std::getline(infile, line)) {
                if (!line.empty()) {
                    virusHashes.push_back(line);
                }
            }
            infile.close();

            if (!virusHashes.empty()) {
                std::lock_guard<std::mutex> lock(gLogMutex);
                std::cout << "[Info] Loaded " << virusHashes.size() 
                          << " virus hashes from " << m_hashFile << std::endl;
            }
        }
    }
    
    if (virusHashes.empty()) {
        virusHashes = {
            "EICAR-SHA256-HASH-EXAMPLE",
            "MALWARE-HASH-EXAMPLE",
            "TROJAN-HASH-SAMPLE"
        };
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cout << "[Info] Using default virus hashes.\n";
    }
    
    return virusHashes;
}

bool ScanWorker::isInfectedBySignature(const std::string& filePath,
                                       const std::vector<std::string>& virusSignatures) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        for (const auto& signature : virusSignatures) {
            if (line.find(signature) != std::string::npos) {
                return true;
            }
        }
    }
    return false;
}

bool ScanWorker::isInfectedByHash(const std::string& filePath,
                                  const std::vector<std::string>& virusHashes) {
    std::string fileHash = computeSHA256(filePath);
    if (fileHash.empty()) {
        return false;
    }
    for (const auto& hash : virusHashes) {
        if (fileHash == hash) {
            return true;
        }
    }
    return false;
}

bool ScanWorker::isInfected(const std::string& filePath,
                            const std::vector<std::string>& virusSignatures,
                            const std::vector<std::string>& virusHashes,
                            bool useBoth) {
    bool infectedBySignature = isInfectedBySignature(filePath, virusSignatures);
    bool infectedByHash = isInfectedByHash(filePath, virusHashes);

    if (useBoth) {
        return infectedBySignature || infectedByHash;
    } else {
        return infectedBySignature;
    }
}

bool ScanWorker::quarantineFile(const std::string& filePath, const std::string& quarantineDir) {
    try {
        fs::path source(filePath);
        fs::path target = fs::path(quarantineDir) / source.filename();
        fs::create_directories(quarantineDir);
        fs::rename(source, target);
        return true;
    } catch (const fs::filesystem_error& e) {
        std::lock_guard<std::mutex> lock(gLogMutex);
        std::cerr << "[Error] Failed to quarantine " << filePath << ": " << e.what() << std::endl;
        return false;
    }
}

void ScanWorker::scanFiles(const std::vector<std::string>& files,
                           const std::vector<std::string>& virusSignatures,
                           const std::vector<std::string>& virusHashes,
                           const std::string& quarantineDir,
                           bool enableQuarantine,
                           std::atomic_bool& keepScanning) {
    for (const auto& filePath : files) {
        if (!keepScanning) {
            std::lock_guard<std::mutex> lock(gLogMutex);
            std::cout << "[Info] Thread stopped early.\n";
            return;
        }
        
        // Increment scanned file count
        ++m_totalFilesScanned;
        
        // Check using both signature and hash detection
        bool infected = isInfected(filePath, virusSignatures, virusHashes, true);
        {
            std::lock_guard<std::mutex> lock(gLogMutex);
            std::cout << "[Scan] " << filePath << " -> " << (infected ? "Infected!" : "Clean") << std::endl;
        }
        
        if (infected) {
            ++m_totalInfected;
        }

        if (infected && enableQuarantine) {
            bool success = quarantineFile(filePath, quarantineDir);
            if (success) {
                ++m_totalQuarantined;
                std::lock_guard<std::mutex> lock(gLogMutex);
                std::cout << "[Quarantine] " << filePath << " moved to " << quarantineDir << std::endl;
            } else {
                std::lock_guard<std::mutex> lock(gLogMutex);
                std::cout << "[Quarantine] Failed to move " << filePath << std::endl;
            }
        }
    }
}

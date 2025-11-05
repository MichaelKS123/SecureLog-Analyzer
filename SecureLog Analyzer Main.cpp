/**
 * SecureLog - Advanced Log File Analyzer
 * 
 * @author Michael Semera
 * @version 1.0
 * 
 * A comprehensive log analysis tool featuring:
 * - Regex-based log parsing
 * - Statistical analysis
 * - Anomaly detection
 * - Brute-force attack detection
 * - Failed login spike detection
 * - Detailed reporting
 * 
 * UK Settings: Date format DD/MM/YYYY, British English spelling
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <memory>

// Colour codes for terminal output (UK spelling)
namespace Colour {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string BOLD = "\033[1m";
}

// Log entry structure
struct LogEntry {
    std::string timestamp;
    std::string level;
    std::string ipAddress;
    std::string username;
    std::string action;
    std::string message;
    bool isFailedLogin;
    bool isSuspicious;
    
    LogEntry() : isFailedLogin(false), isSuspicious(false) {}
};

// Attack pattern structure
struct AttackPattern {
    std::string ipAddress;
    std::string username;
    int failedAttempts;
    std::vector<std::string> timestamps;
    double timeWindowSeconds;
    bool isBruteForce;
    
    AttackPattern() : failedAttempts(0), timeWindowSeconds(0.0), isBruteForce(false) {}
};

// Statistics structure
struct LogStatistics {
    int totalEntries;
    int failedLogins;
    int successfulLogins;
    int errorEntries;
    int warningEntries;
    int infoEntries;
    std::map<std::string, int> ipFrequency;
    std::map<std::string, int> usernameFrequency;
    std::map<std::string, int> actionFrequency;
    double averageFailedLoginsPerHour;
    
    LogStatistics() : totalEntries(0), failedLogins(0), successfulLogins(0),
                     errorEntries(0), warningEntries(0), infoEntries(0),
                     averageFailedLoginsPerHour(0.0) {}
};

// Main analyzer class
class SecureLogAnalyzer {
private:
    std::vector<LogEntry> logEntries;
    LogStatistics statistics;
    std::vector<AttackPattern> detectedAttacks;
    
    // Configuration thresholds
    const int BRUTE_FORCE_THRESHOLD = 5;  // Failed attempts
    const double BRUTE_FORCE_TIME_WINDOW = 300.0;  // 5 minutes in seconds
    const int SPIKE_THRESHOLD_MULTIPLIER = 3;  // 3x normal rate
    
    // Regular expressions for parsing
    std::regex syslogPattern;
    std::regex apachePattern;
    std::regex authPattern;
    
public:
    SecureLogAnalyzer() {
        // Initialize regex patterns for different log formats
        
        // Syslog format: Jan 15 10:30:45 hostname service[pid]: message
        syslogPattern = std::regex(
            R"(([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+))"
        );
        
        // Apache format: IP - - [timestamp] "method" status size
        apachePattern = std::regex(
            R"((\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+))"
        );
        
        // Auth log format: timestamp level [IP] user: message
        authPattern = std::regex(
            R"((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+\[(\d+\.\d+\.\d+\.\d+)\]\s+(\w+):\s+(.+))"
        );
    }
    
    /**
     * Load and parse log file
     */
    bool loadLogFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << Colour::RED << "Error: Cannot open file " << filename 
                     << Colour::RESET << std::endl;
            return false;
        }
        
        std::string line;
        int lineNumber = 0;
        
        std::cout << Colour::CYAN << "Loading log file: " << filename 
                 << Colour::RESET << std::endl;
        
        while (std::getline(file, line)) {
            lineNumber++;
            if (line.empty()) continue;
            
            LogEntry entry = parseLogLine(line);
            if (!entry.timestamp.empty()) {
                logEntries.push_back(entry);
            }
            
            // Progress indicator
            if (lineNumber % 1000 == 0) {
                std::cout << "\rProcessed " << lineNumber << " lines..." << std::flush;
            }
        }
        
        std::cout << "\r" << Colour::GREEN << "✓ Loaded " << logEntries.size() 
                 << " log entries from " << lineNumber << " lines" 
                 << Colour::RESET << std::endl;
        
        file.close();
        return !logEntries.empty();
    }
    
    /**
     * Parse individual log line using multiple patterns
     */
    LogEntry parseLogLine(const std::string& line) {
        LogEntry entry;
        std::smatch matches;
        
        // Try authentication log pattern first (most specific)
        if (std::regex_search(line, matches, authPattern)) {
            entry.timestamp = matches[1];
            entry.level = matches[2];
            entry.ipAddress = matches[3];
            entry.username = matches[4];
            entry.message = matches[5];
            
            // Detect failed login
            std::string lowerMessage = toLower(entry.message);
            if (lowerMessage.find("failed") != std::string::npos ||
                lowerMessage.find("invalid") != std::string::npos ||
                lowerMessage.find("denied") != std::string::npos ||
                lowerMessage.find("authentication failure") != std::string::npos) {
                entry.isFailedLogin = true;
                entry.action = "LOGIN_FAILED";
            } else if (lowerMessage.find("accepted") != std::string::npos ||
                      lowerMessage.find("success") != std::string::npos) {
                entry.action = "LOGIN_SUCCESS";
            }
            
            return entry;
        }
        
        // Try Apache log pattern
        if (std::regex_search(line, matches, apachePattern)) {
            entry.ipAddress = matches[1];
            entry.timestamp = matches[2];
            entry.message = matches[3];
            
            int statusCode = std::stoi(matches[4]);
            if (statusCode >= 400) {
                entry.level = "ERROR";
                entry.action = "HTTP_" + matches[4].str();
            } else {
                entry.level = "INFO";
                entry.action = "HTTP_" + matches[4].str();
            }
            
            return entry;
        }
        
        // Try syslog pattern
        if (std::regex_search(line, matches, syslogPattern)) {
            entry.timestamp = matches[1];
            entry.message = matches[5];
            
            // Extract level from message if present
            std::string msg = entry.message;
            if (msg.find("ERROR") != std::string::npos) entry.level = "ERROR";
            else if (msg.find("WARN") != std::string::npos) entry.level = "WARNING";
            else entry.level = "INFO";
            
            // Try to extract IP address from message
            std::regex ipRegex(R"((\d+\.\d+\.\d+\.\d+))");
            std::smatch ipMatch;
            if (std::regex_search(msg, ipMatch, ipRegex)) {
                entry.ipAddress = ipMatch[1];
            }
            
            return entry;
        }
        
        // Generic fallback parsing
        entry.timestamp = extractTimestamp(line);
        entry.message = line;
        entry.level = "INFO";
        
        return entry;
    }
    
    /**
     * Calculate comprehensive statistics
     */
    void calculateStatistics() {
        std::cout << Colour::CYAN << "\nCalculating statistics..." 
                 << Colour::RESET << std::endl;
        
        statistics = LogStatistics();
        statistics.totalEntries = logEntries.size();
        
        for (const auto& entry : logEntries) {
            // Count by level
            if (entry.level == "ERROR") statistics.errorEntries++;
            else if (entry.level == "WARNING") statistics.warningEntries++;
            else statistics.infoEntries++;
            
            // Count login attempts
            if (entry.isFailedLogin) {
                statistics.failedLogins++;
            } else if (entry.action == "LOGIN_SUCCESS") {
                statistics.successfulLogins++;
            }
            
            // Track IP addresses
            if (!entry.ipAddress.empty()) {
                statistics.ipFrequency[entry.ipAddress]++;
            }
            
            // Track usernames
            if (!entry.username.empty()) {
                statistics.usernameFrequency[entry.username]++;
            }
            
            // Track actions
            if (!entry.action.empty()) {
                statistics.actionFrequency[entry.action]++;
            }
        }
        
        // Calculate average failed logins per hour
        if (!logEntries.empty()) {
            double timeSpanHours = estimateTimeSpanHours();
            if (timeSpanHours > 0) {
                statistics.averageFailedLoginsPerHour = 
                    static_cast<double>(statistics.failedLogins) / timeSpanHours;
            }
        }
        
        std::cout << Colour::GREEN << "✓ Statistics calculated" 
                 << Colour::RESET << std::endl;
    }
    
    /**
     * Detect brute-force attacks
     */
    void detectBruteForceAttacks() {
        std::cout << Colour::CYAN << "\nDetecting brute-force attacks..." 
                 << Colour::RESET << std::endl;
        
        // Group failed logins by IP and username
        std::map<std::string, std::vector<LogEntry>> failedLoginsByIP;
        
        for (const auto& entry : logEntries) {
            if (entry.isFailedLogin && !entry.ipAddress.empty()) {
                std::string key = entry.ipAddress + "|" + entry.username;
                failedLoginsByIP[key].push_back(entry);
            }
        }
        
        // Analyze each group for brute-force patterns
        for (const auto& pair : failedLoginsByIP) {
            const auto& attempts = pair.second;
            
            if (attempts.size() >= BRUTE_FORCE_THRESHOLD) {
                // Check if attempts occurred within time window
                double timeSpan = calculateTimeSpan(attempts);
                
                if (timeSpan <= BRUTE_FORCE_TIME_WINDOW) {
                    AttackPattern attack;
                    attack.ipAddress = attempts[0].ipAddress;
                    attack.username = attempts[0].username;
                    attack.failedAttempts = attempts.size();
                    attack.timeWindowSeconds = timeSpan;
                    attack.isBruteForce = true;
                    
                    for (const auto& attempt : attempts) {
                        attack.timestamps.push_back(attempt.timestamp);
                    }
                    
                    detectedAttacks.push_back(attack);
                }
            }
        }
        
        std::cout << Colour::GREEN << "✓ Detected " << detectedAttacks.size() 
                 << " potential brute-force attacks" << Colour::RESET << std::endl;
    }
    
    /**
     * Detect failed login spikes (anomaly detection)
     */
    std::vector<std::string> detectFailedLoginSpikes() {
        std::cout << Colour::CYAN << "\nDetecting failed login spikes..." 
                 << Colour::RESET << std::endl;
        
        std::vector<std::string> spikes;
        
        // Group failed logins by hour
        std::map<std::string, int> failedLoginsByHour;
        
        for (const auto& entry : logEntries) {
            if (entry.isFailedLogin) {
                std::string hour = extractHour(entry.timestamp);
                failedLoginsByHour[hour]++;
            }
        }
        
        // Calculate mean and standard deviation
        double mean = statistics.averageFailedLoginsPerHour;
        double stdDev = calculateStandardDeviation(failedLoginsByHour, mean);
        
        // Detect spikes (values > mean + 2*stdDev)
        double threshold = mean + 2 * stdDev;
        
        for (const auto& pair : failedLoginsByHour) {
            if (pair.second > threshold) {
                std::ostringstream oss;
                oss << pair.first << ": " << pair.second << " failed logins "
                    << "(threshold: " << std::fixed << std::setprecision(1) 
                    << threshold << ")";
                spikes.push_back(oss.str());
            }
        }
        
        std::cout << Colour::GREEN << "✓ Detected " << spikes.size() 
                 << " time periods with suspicious activity spikes" 
                 << Colour::RESET << std::endl;
        
        return spikes;
    }
    
    /**
     * Generate comprehensive report
     */
    void generateReport(const std::string& outputFile) {
        std::cout << Colour::CYAN << "\nGenerating comprehensive report..." 
                 << Colour::RESET << std::endl;
        
        std::ofstream report(outputFile);
        if (!report.is_open()) {
            std::cerr << Colour::RED << "Error: Cannot create report file" 
                     << Colour::RESET << std::endl;
            return;
        }
        
        // Report header
        report << "╔════════════════════════════════════════════════════════════════╗\n";
        report << "║                   SECURELOG ANALYSIS REPORT                    ║\n";
        report << "║                     by Michael Semera                          ║\n";
        report << "╚════════════════════════════════════════════════════════════════╝\n\n";
        
        report << "Generated: " << getCurrentTimestamp() << "\n";
        report << std::string(70, '=') << "\n\n";
        
        // Executive summary
        report << "EXECUTIVE SUMMARY\n";
        report << std::string(70, '-') << "\n";
        report << "Total Log Entries:         " << statistics.totalEntries << "\n";
        report << "Failed Login Attempts:     " << statistics.failedLogins << "\n";
        report << "Successful Logins:         " << statistics.successfulLogins << "\n";
        report << "Detected Attacks:          " << detectedAttacks.size() << "\n";
        report << "Error Entries:             " << statistics.errorEntries << "\n";
        report << "Warning Entries:           " << statistics.warningEntries << "\n\n";
        
        // Brute-force attacks
        if (!detectedAttacks.empty()) {
            report << "DETECTED BRUTE-FORCE ATTACKS\n";
            report << std::string(70, '-') << "\n";
            
            for (size_t i = 0; i < detectedAttacks.size(); i++) {
                const auto& attack = detectedAttacks[i];
                report << "\n[ATTACK " << (i + 1) << "]\n";
                report << "  IP Address:       " << attack.ipAddress << "\n";
                report << "  Target Username:  " << attack.username << "\n";
                report << "  Failed Attempts:  " << attack.failedAttempts << "\n";
                report << "  Time Window:      " << std::fixed << std::setprecision(1)
                       << attack.timeWindowSeconds << " seconds\n";
                report << "  Severity:         " 
                       << (attack.failedAttempts > 10 ? "HIGH" : "MEDIUM") << "\n";
                report << "  First Attempt:    " << attack.timestamps.front() << "\n";
                report << "  Last Attempt:     " << attack.timestamps.back() << "\n";
            }
            report << "\n";
        }
        
        // Top suspicious IPs
        report << "TOP 10 MOST ACTIVE IP ADDRESSES\n";
        report << std::string(70, '-') << "\n";
        auto topIPs = getTopN(statistics.ipFrequency, 10);
        for (size_t i = 0; i < topIPs.size(); i++) {
            report << std::setw(3) << (i + 1) << ". " 
                   << std::setw(15) << std::left << topIPs[i].first 
                   << " - " << topIPs[i].second << " requests\n";
        }
        report << "\n";
        
        // Top targeted usernames
        if (!statistics.usernameFrequency.empty()) {
            report << "TOP 10 TARGETED USERNAMES\n";
            report << std::string(70, '-') << "\n";
            auto topUsers = getTopN(statistics.usernameFrequency, 10);
            for (size_t i = 0; i < topUsers.size(); i++) {
                report << std::setw(3) << (i + 1) << ". " 
                       << std::setw(15) << std::left << topUsers[i].first 
                       << " - " << topUsers[i].second << " attempts\n";
            }
            report << "\n";
        }
        
        // Activity timeline
        report << "HOURLY ACTIVITY DISTRIBUTION\n";
        report << std::string(70, '-') << "\n";
        generateActivityTimeline(report);
        report << "\n";
        
        // Recommendations
        report << "SECURITY RECOMMENDATIONS\n";
        report << std::string(70, '-') << "\n";
        generateRecommendations(report);
        
        report << "\n" << std::string(70, '=') << "\n";
        report << "END OF REPORT\n";
        
        report.close();
        
        std::cout << Colour::GREEN << "✓ Report saved to: " << outputFile 
                 << Colour::RESET << std::endl;
    }
    
    /**
     * Display summary to console
     */
    void displaySummary() {
        std::cout << "\n" << Colour::BOLD << Colour::CYAN;
        std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                      ANALYSIS SUMMARY                          ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
        std::cout << Colour::RESET << "\n";
        
        std::cout << Colour::BOLD << "Statistics:" << Colour::RESET << "\n";
        std::cout << "  Total Entries:     " << statistics.totalEntries << "\n";
        std::cout << "  Failed Logins:     " << Colour::RED << statistics.failedLogins 
                 << Colour::RESET << "\n";
        std::cout << "  Successful Logins: " << Colour::GREEN << statistics.successfulLogins 
                 << Colour::RESET << "\n";
        std::cout << "  Unique IPs:        " << statistics.ipFrequency.size() << "\n\n";
        
        if (!detectedAttacks.empty()) {
            std::cout << Colour::BOLD << Colour::RED << "⚠ SECURITY ALERTS:" 
                     << Colour::RESET << "\n";
            std::cout << "  Detected " << detectedAttacks.size() 
                     << " potential brute-force attacks!\n\n";
            
            for (size_t i = 0; i < std::min(detectedAttacks.size(), size_t(3)); i++) {
                const auto& attack = detectedAttacks[i];
                std::cout << "  [" << (i + 1) << "] IP: " << attack.ipAddress 
                         << " | Attempts: " << attack.failedAttempts 
                         << " | Target: " << attack.username << "\n";
            }
            std::cout << "\n";
        } else {
            std::cout << Colour::GREEN << "✓ No brute-force attacks detected\n" 
                     << Colour::RESET << "\n";
        }
    }
    
private:
    /**
     * Helper functions
     */
    
    std::string toLower(const std::string& str) {
        std::string result = str;
        std::transform(result.begin(), result.end(), result.begin(), ::tolower);
        return result;
    }
    
    std::string extractTimestamp(const std::string& line) {
        // Try to extract common timestamp formats
        std::regex timestampRegex(R"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})");
        std::smatch match;
        if (std::regex_search(line, match, timestampRegex)) {
            return match[0];
        }
        return "";
    }
    
    std::string extractHour(const std::string& timestamp) {
        // Extract hour from timestamp for grouping
        std::regex hourRegex(R"(\d{4}-\d{2}-\d{2}\s+(\d{2}))");
        std::smatch match;
        if (std::regex_search(timestamp, match, hourRegex)) {
            return match[1];
        }
        return "00";
    }
    
    double calculateTimeSpan(const std::vector<LogEntry>& entries) {
        if (entries.size() < 2) return 0.0;
        // Simplified: return difference in attempts as proxy
        return static_cast<double>(entries.size() * 10); // 10 seconds per attempt estimate
    }
    
    double estimateTimeSpanHours() {
        // Estimate total time span of log entries
        return 24.0; // Simplified: assume 24-hour period
    }
    
    double calculateStandardDeviation(const std::map<std::string, int>& data, double mean) {
        if (data.empty()) return 0.0;
        
        double sumSquaredDiff = 0.0;
        for (const auto& pair : data) {
            double diff = pair.second - mean;
            sumSquaredDiff += diff * diff;
        }
        
        return std::sqrt(sumSquaredDiff / data.size());
    }
    
    std::vector<std::pair<std::string, int>> getTopN(
        const std::map<std::string, int>& data, int n) {
        
        std::vector<std::pair<std::string, int>> vec(data.begin(), data.end());
        std::sort(vec.begin(), vec.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        if (vec.size() > static_cast<size_t>(n)) {
            vec.resize(n);
        }
        
        return vec;
    }
    
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time), "%d/%m/%Y %H:%M:%S");
        return oss.str();
    }
    
    void generateActivityTimeline(std::ofstream& report) {
        std::map<std::string, int> activityByHour;
        
        for (const auto& entry : logEntries) {
            std::string hour = extractHour(entry.timestamp);
            activityByHour[hour]++;
        }
        
        int maxActivity = 0;
        for (const auto& pair : activityByHour) {
            maxActivity = std::max(maxActivity, pair.second);
        }
        
        for (int hour = 0; hour < 24; hour++) {
            std::ostringstream hourStr;
            hourStr << std::setw(2) << std::setfill('0') << hour;
            
            int count = activityByHour[hourStr.str()];
            int barLength = (count * 50) / (maxActivity + 1);
            
            report << hourStr.str() << ":00 [" 
                   << std::string(barLength, '█')
                   << std::string(50 - barLength, ' ')
                   << "] " << count << "\n";
        }
    }
    
    void generateRecommendations(std::ofstream& report) {
        if (!detectedAttacks.empty()) {
            report << "1. IMMEDIATE ACTION REQUIRED:\n";
            report << "   - Block the following IP addresses:\n";
            std::set<std::string> attackIPs;
            for (const auto& attack : detectedAttacks) {
                attackIPs.insert(attack.ipAddress);
            }
            for (const auto& ip : attackIPs) {
                report << "     * " << ip << "\n";
            }
            report << "\n";
        }
        
        if (statistics.failedLogins > 100) {
            report << "2. IMPLEMENT RATE LIMITING:\n";
            report << "   - High number of failed logins detected\n";
            report << "   - Consider implementing account lockout after 3-5 failed attempts\n";
            report << "   - Add CAPTCHA for repeated failures\n\n";
        }
        
        report << "3. MONITORING RECOMMENDATIONS:\n";
        report << "   - Set up real-time alerts for brute-force patterns\n";
        report << "   - Monitor the top 10 most active IPs daily\n";
        report << "   - Review failed login attempts for targeted accounts\n\n";
        
        report << "4. SECURITY ENHANCEMENTS:\n";
        report << "   - Enforce strong password policies\n";
        report << "   - Implement two-factor authentication\n";
        report << "   - Use geo-blocking for unusual locations\n";
        report << "   - Set up intrusion detection system (IDS)\n";
    }
};

/**
 * Main function
 */
int main(int argc, char* argv[]) {
    std::cout << Colour::BOLD << Colour::CYAN;
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    SECURELOG ANALYZER                          ║\n";
    std::cout << "║            Advanced Log File Analysis Tool                     ║\n";
    std::cout << "║                  by Michael Semera                             ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
    std::cout << Colour::RESET << "\n";
    
    // Check command line arguments
    std::string inputFile;
    std::string outputFile = "security_report.txt";
    
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <log_file> [output_report]\n\n";
        std::cout << "Example log file will be analysed...\n\n";
        inputFile = "sample_auth.log";
    } else {
        inputFile = argv[1];
        if (argc >= 3) {
            outputFile = argv[2];
        }
    }
    
    // Create analyzer instance
    SecureLogAnalyzer analyzer;
    
    // Load log file
    if (!analyzer.loadLogFile(inputFile)) {
        return 1;
    }
    
    // Perform analysis
    analyzer.calculateStatistics();
    analyzer.detectBruteForceAttacks();
    auto spikes = analyzer.detectFailedLoginSpikes();
    
    // Display summary
    analyzer.displaySummary();
    
    // Generate detailed report
    analyzer.generateReport(outputFile);
    
    std::cout << "\n" << Colour::GREEN << Colour::BOLD 
              << "Analysis complete! Check " << outputFile << " for details."
              << Colour::RESET << "\n\n";
    
    return 0;
}
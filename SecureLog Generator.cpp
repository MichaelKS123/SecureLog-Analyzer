/**
 * Sample Log File Generator
 * Creates realistic authentication logs for testing
 * 
 * @author Michael Semera
 */

#include <iostream>
#include <fstream>
#include <random>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

class LogGenerator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
    std::vector<std::string> normalIPs = {
        "192.168.1.100", "192.168.1.101", "192.168.1.102",
        "10.0.0.50", "10.0.0.51", "10.0.0.52"
    };
    
    std::vector<std::string> attackerIPs = {
        "203.0.113.42", "198.51.100.88", "192.0.2.123"
    };
    
    std::vector<std::string> usernames = {
        "admin", "root", "user", "john", "sarah", "michael",
        "administrator", "test", "guest"
    };
    
    std::vector<std::string> successMessages = {
        "Accepted password for",
        "Successful authentication for",
        "User logged in successfully"
    };
    
    std::vector<std::string> failureMessages = {
        "Failed password for",
        "Invalid user",
        "Authentication failure for",
        "Denied access to",
        "Failed login attempt for"
    };
    
public:
    LogGenerator() : gen(rd()) {}
    
    void generateSampleLog(const std::string& filename, int entries) {
        std::ofstream log(filename);
        if (!log.is_open()) {
            std::cerr << "Error: Cannot create log file\n";
            return;
        }
        
        std::cout << "Generating " << entries << " log entries...\n";
        
        // Generate timeline over 24 hours
        int hour = 0, minute = 0, second = 0;
        
        for (int i = 0; i < entries; i++) {
            // Progress time
            second += getRandomInt(5, 30);
            if (second >= 60) {
                minute += second / 60;
                second %= 60;
            }
            if (minute >= 60) {
                hour += minute / 60;
                minute %= 60;
            }
            hour %= 24;
            
            std::string timestamp = formatTimestamp(hour, minute, second);
            std::string level;
            std::string ip;
            std::string username;
            std::string message;
            
            // 10% chance of brute-force attack pattern
            if (getRandomInt(1, 100) <= 10) {
                // Brute force: rapid failed attempts from same IP
                ip = attackerIPs[getRandomInt(0, attackerIPs.size() - 1)];
                username = usernames[getRandomInt(0, 2)]; // Target common users
                level = "ERROR";
                message = failureMessages[getRandomInt(0, failureMessages.size() - 1)] 
                         + " " + username;
                
                // Generate cluster of attempts
                for (int j = 0; j < getRandomInt(3, 8); j++) {
                    log << timestamp << " " << level << " [" << ip << "] " 
                        << username << ": " << message << "\n";
                    
                    second += getRandomInt(1, 5);
                    timestamp = formatTimestamp(hour, minute, second);
                }
            }
            // 70% normal successful logins
            else if (getRandomInt(1, 100) <= 70) {
                ip = normalIPs[getRandomInt(0, normalIPs.size() - 1)];
                username = usernames[getRandomInt(3, usernames.size() - 1)];
                level = "INFO";
                message = successMessages[getRandomInt(0, successMessages.size() - 1)] 
                         + " " + username;
            }
            // 20% normal failed logins
            else {
                ip = normalIPs[getRandomInt(0, normalIPs.size() - 1)];
                username = usernames[getRandomInt(0, usernames.size() - 1)];
                level = "WARNING";
                message = failureMessages[getRandomInt(0, failureMessages.size() - 1)] 
                         + " " + username;
            }
            
            log << timestamp << " " << level << " [" << ip << "] " 
                << username << ": " << message << "\n";
        }
        
        log.close();
        std::cout << "✓ Generated sample log: " << filename << "\n";
    }
    
private:
    int getRandomInt(int min, int max) {
        std::uniform_int_distribution<> dis(min, max);
        return dis(gen);
    }
    
    std::string formatTimestamp(int hour, int minute, int second) {
        std::ostringstream oss;
        oss << "2024-11-05 "
            << std::setw(2) << std::setfill('0') << hour << ":"
            << std::setw(2) << std::setfill('0') << minute << ":"
            << std::setw(2) << std::setfill('0') << second;
        return oss.str();
    }
};

int main(int argc, char* argv[]) {
    std::string filename = "sample_auth.log";
    int entries = 1000;
    
    if (argc >= 2) {
        filename = argv[1];
    }
    if (argc >= 3) {
        entries = std::stoi(argv[2]);
    }
    
    LogGenerator generator;
    generator.generateSampleLog(filename, entries);
    
    std::cout << "\nYou can now run: ./securelog " << filename << "\n";
    
    return 0;
}
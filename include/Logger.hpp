#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <string_view>
#include <mutex>
#include <filesystem>
#include <iostream>
#include <cstring>      // strerror
#include <fcntl.h>      // open, O_WRONLY...
#include <unistd.h>     // dup2, close, STDOUT_FILENO

namespace SST {
    
    class Logger {
    public:
        static bool init(std::string_view log_path){
            std::lock_guard<std::mutex> lock(mutex_);
            if(log_path.empty()) return false; // 경로 없으면 실패 처리

            if(!makeLogPath(log_path)){
                std::cerr << "[Logger] Failed to create log directory." << "\n";
                return false;
            }

            if(!redirectOutput(log_path)){
                std::cerr << "[Logger] Failed to redirect log output." << "\n";
                return false;
            }
            return true;
        }

    private:
        static inline std::mutex mutex_;

        static bool redirectOutput(std::string_view log_path){
            // 1. 로그 파일 열기
            int fd = open(std::string(log_path).c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
            if(fd == -1) {
                // 아직 리다이렉션 전이므로 화면에 에러 출력 가능
                std::cerr << "[Logger] Failed to open log file: " << strerror(errno) << "\n";
                return false;
            }

            // 2. STDOUT 리다이렉트 (복구 생각하지 말고 덮어쓰기)
            if(dup2(fd, STDOUT_FILENO) == -1){
                std::cerr << "[Logger] Failed to dup2 stdout: " << strerror(errno) << "\n";
                close(fd);
                return false;
            }

            // 3. STDERR 리다이렉트
            if(dup2(fd, STDERR_FILENO) == -1){
                // 이미 stdout은 파일로 넘어갔으므로, 이 에러는 파일에 기록될 확률이 높음
                std::cerr << "[Logger] Failed to dup2 stderr: " << strerror(errno) << "\n";
                close(fd);
                return false;
            }
            std::cout << "[Logger] Log output redirected to " << log_path << "\n";

            // 4. 원본 fd 닫기 (이제 1번, 2번이 파일을 가리키므로 fd는 필요 없음)
            close(fd);
            return true;
        }

        static bool makeLogPath(std::string_view log_path){
            std::filesystem::path path(log_path);
            std::filesystem::path dir = path.parent_path();
            try {
                if(!dir.empty() && !std::filesystem::exists(dir)){
                    std::filesystem::create_directories(dir);
                    std::cout << "[Logger] Created log directory: " << dir.string() << "\n";
                }
                return true;
            } catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "[Logger] Filesystem error: " << e.what() << "\n";
                return false;
            }
        }
    };
}

#endif
#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <string_view>
#include <mutex>
#include <filesystem>
#include <iostream>
#include <fcntl.h>      // open, O_WRONLY...
#include <unistd.h>     // dup2, close, STDOUT_FILENO

namespace SST {
    
    class Logger{
        public:

        // 로그설정 초기화
        // 로그 디렉토리 생성시도
        // dup2를 사용하여 stdout과 stderr를 지정된 파일로 리다이렉트
        static bool init(std::string_view log_path){
            std::lock_guard<std::mutex> lock(mutex_); // 스레드 안전성 확보
            if(log_path.empty()) return true;

            if(!makeLogPath(log_path)){
                std::cerr << "[Logger] Failed to create log directory." << std::endl;
                return false;
            }

            if(!redirectOutput(log_path)){
                std::cerr << "[Logger] Failed to redirect log output." << std::endl;
                return false;
            }
            return true;
        }

        private:
        static bool redirectOutput(std::string_view log_path){
            if(log_path.empty()) {
                std::cerr << "[Logger]Log path is empty, plz check config." << std::endl;
                return false;
            }
            int fd = open(std::string(log_path).c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644); // 0644 -> rw-r--r--
            if(fd == -1) return false;

            // stdout을 파일 디스크립터로 리다이렉트
            if(dup2(fd, STDOUT_FILENO) == -1){
                close(fd);
                return false;
            }

            // stderr을 파일 디스크립터로 리다이렉트
            if(dup2(fd, STDERR_FILENO) == -1){
                close(fd);
                return false;
            }
            close(fd);
            return true;
        }

        static bool makeLogPath(std::string_view log_path){
            // 로그 경로에서 디렉토리 경로와 로그파일 이름 분리
            std::filesystem::path path(log_path);
            std::filesystem::path dir = path.parent_path();
            try {
                if(!dir.empty() && !std::filesystem::exists(dir)){ // 디렉토리가 존재하지 않으면 생성
                    std::filesystem::create_directories(dir);
                }
                return true;
            } catch (...){
                std::cerr << "[Logger] Filesystem error." << std::endl;
                return false;
            }
        }

        private:
        static inline std::mutex mutex_;
    };
}


#endif
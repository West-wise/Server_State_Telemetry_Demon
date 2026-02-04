#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <string>
#include <string_view>
#include <mutex>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <cstring>
#include <queue>
#include <thread>
#include <condition_variable>
#include <atomic>

namespace SST {
    
    class Logger {
    public:
        // Async Logger 초기화
        static bool init(std::string_view log_path) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_) return true; // 이미 초기화됨

            try {
                // 디렉토리 생성
                std::filesystem::path path(log_path);
                std::filesystem::path dir = path.parent_path();
                if (!dir.empty() && !std::filesystem::exists(dir)) {
                    std::filesystem::create_directories(dir);
                }

                // 파일 열기
                log_file_.open(path, std::ios::out | std::ios::app);
                if (!log_file_.is_open()) {
                    std::cerr << "[Logger] Failed to open log file." << std::endl;
                    return false;
                }
            } catch (const std::exception& e) { // 기존의 리다이렉트 방식을 사용X, 로깅 스레드를 사용해서 비동기적 처리 채택
                std::cerr << "[Logger] Init Error: " << e.what() << std::endl;
                return false;
            }

            // 워커 스레드 시작
            running_ = true;
            worker_thread_ = std::thread(processQueue);
            instance_ = true;

            std::cout << "[Logger] Async logger started. Path: " << log_path << std::endl;
            return true;
        }

        static void log(const std::string& msg) {
            if (instance_) {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                log_queue_.push(msg);
            }
            cv_.notify_one();
        }

        static void shutdown() {
            running_ = false;
            cv_.notify_all();
            if (worker_thread_.joinable()) {
                worker_thread_.join();
            }
            if (log_file_.is_open()) {
                log_file_.close();
            }
        }

    private:
        static inline std::mutex mutex_;                    // 로깅 스레드 생성, 소멸 동기화
        static inline std::mutex queue_mutex_;              // 로그 큐 동기화
        static inline std::condition_variable cv_;          // 로그 큐 알림 -> 로그 큐 사용 가능한 시점 알림
        static inline std::queue<std::string> log_queue_;   // 로그 큐
        static inline std::thread worker_thread_;           // 로그 처리 스레드
        static inline std::atomic<bool> running_{false};    // 실행 상태 플래그
        static inline std::ofstream log_file_;              // 로그 파일
        static inline bool instance_ = false;               // 인스턴스 플래그

        static void processQueue() {
            while (running_) {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                cv_.wait(lock, [] { return !log_queue_.empty() || !running_; });

                while (!log_queue_.empty()) {
                    std::string msg = log_queue_.front();
                    log_queue_.pop();
                    
                    // 파일 출력
                    if (log_file_.is_open()) {
                        log_file_ << msg << std::endl;
                    }
                }
            }
        }
    };
}

#endif // LOGGER_HPP
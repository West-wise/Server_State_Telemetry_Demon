#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <string_view>
#include <thread>

namespace SST {

class Logger {
public:
  // 1. 기존과 동일한 정적(Static) API 제공 -> 다른 파일들 수정 불필요
  static bool init(std::string_view log_path) {
    return getInstance().initImpl(log_path);
  }

  static void log(const std::string &msg) { getInstance().logImpl(msg); }

  static void shutdown() { getInstance().shutdownImpl(); }

private:
  // 2. Meyers Singleton 인스턴스 획득
  static Logger &getInstance() {
    static Logger instance;
    return instance;
  }

  // 3. 생성자 및 소멸자 (RAII 보장)
  Logger() = default;
  ~Logger() {
    shutdownImpl(); // 메인에서 깜빡해도 프로그램 종료 시 자동 정리됨
  }

  // 복사 및 대입 방지
  Logger(const Logger &) = delete;            // 복사
  Logger &operator=(const Logger &) = delete; // 대입 방지

  // 4. 인스턴스 멤버 변수로 변경 (더 이상 static inline이 아님)
  std::mutex init_mutex_;
  std::mutex queue_mutex_;
  std::condition_variable cv_;
  std::queue<std::string> log_queue_;
  std::thread worker_thread_;
  std::atomic<bool> running_{false};
  std::ofstream log_file_;
  std::atomic<bool> is_initialized_{false}; // Data Race 방지용 atomic

  // --- 실제 구현부 ---
  bool initImpl(std::string_view log_path) {
    std::lock_guard<std::mutex> lock(init_mutex_); // 생성하기 위한 락 획득
    if (is_initialized_) // 이미 초기화 되어있다면 생략
      return true;

    try {
      std::filesystem::path path(log_path);
      std::filesystem::path dir = path.parent_path();
      if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
      }

      log_file_.open(path, std::ios::out | std::ios::app);
      if (!log_file_.is_open()) {
        std::cerr << "[Logger] Failed to open log file." << std::endl;
        return false;
      }
    } catch (const std::exception &e) {
      std::cerr << "[Logger] Init Error: " << e.what() << std::endl;
      return false;
    }

    running_ = true;
    worker_thread_ = std::thread(&Logger::processQueue, this);
    is_initialized_ = true;

    std::cout << "[Logger] Async logger started. Path: " << log_path
              << std::endl;
    return true;
  }

  void logImpl(const std::string &msg) {
    if (!is_initialized_) // 아직 로깅 스레드가 초기화 되지 않은 상태에서 로거를
                          // 호출하면 안됨
      return;

    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      log_queue_.push(msg);
    }
    cv_.notify_one();
  }

  void shutdownImpl() {
    // 이미 종료되었다면 중복 실행 방지
    if (!running_.exchange(false))
      return;

    cv_.notify_all();

    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }

    if (log_file_.is_open()) {
      log_file_.close();
    }

    is_initialized_ = false;
  }

  void processQueue() {
    while (running_) {
      std::queue<std::string> local_queue; // 지역 큐 (빈 바구니)

      {
        std::unique_lock<std::mutex> lock(queue_mutex_); // 락 획득
        cv_.wait(lock, [this] { return !log_queue_.empty() || !running_; });

        // 큐 통째로 스왑 (O(1) 시간복잡도로 찰나의 순간에 포인터만 바뀜)
        std::swap(log_queue_, local_queue);
      } // <- 여기서 락이 즉시 풀림! 이제 다른 스레드들이 방해받지 않고 log() 호출 가능

      // 락이 없는 자유로운 상태에서 파일 I/O 진행 (느려도 메인 스레드에 영향 없음)
      while (!local_queue.empty()) {
        std::string msg = local_queue.front();
        local_queue.pop();

        if (log_file_.is_open()) {
          log_file_ << msg << '\n';
        }
      }
    }
    // 스레드 종료 직전 남은 큐 강제 플러시
    while (!log_queue_.empty()) {
      if (log_file_.is_open()) {
        log_file_ << log_queue_.front() << '\n';
      }
      log_queue_.pop();
    }
  }
};
} // namespace SST

#endif // LOGGER_HPP
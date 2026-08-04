#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/spdlog.h>

namespace SST {

class Logger {
public:
  struct Options {
    std::string path;
    std::string level = "info";
    std::string pattern = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";
    std::size_t max_size_bytes = 10U * 1024U * 1024U;
    std::size_t max_files = 5U;
  };

  static bool init(const Options &options) {
    return getInstance().initImpl(options);
  }

  static bool init(std::string_view log_path) {
    Options options;
    options.path = log_path;
    return init(options);
  }

  static void log(const std::string &msg) { getInstance().logImpl(msg); }

  static void shutdown() { getInstance().shutdownImpl(); }

private:
  static Logger &getInstance() {
    static Logger instance;
    return instance;
  }

  Logger() = default;
  ~Logger() { shutdownImpl(); }

  Logger(const Logger &) = delete;
  Logger &operator=(const Logger &) = delete;

  std::mutex mutex_;
  std::shared_ptr<spdlog::logger> logger_;

  bool initImpl(const Options &options) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logger_) {
      return true;
    }

    try {
      const std::filesystem::path path(options.path);
      const std::filesystem::path directory = path.parent_path();
      if (!directory.empty() && !std::filesystem::exists(directory)) {
        std::filesystem::create_directories(directory);
      }

      const std::size_t max_size_bytes =
          options.max_size_bytes == 0U ? 10U * 1024U * 1024U
                                       : options.max_size_bytes;
      const std::size_t max_files = options.max_files == 0U ? 1U
                                                            : options.max_files;

      logger_ = spdlog::create_async<spdlog::sinks::rotating_file_sink_mt>(
          "sstd", path.string(), max_size_bytes, max_files, false);
      logger_->set_pattern(options.pattern);
      logger_->set_level(spdlog::level::from_str(options.level));
      logger_->flush_on(spdlog::level::info);
    } catch (const std::exception &e) {
      std::cerr << "[Logger] Init Error: " << e.what() << std::endl;
      logger_.reset();
      return false;
    }

    std::cout << "[Logger] Async logger started. Path: " << options.path
              << std::endl;
    return true;
  }

  void logImpl(const std::string &msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (logger_) {
      logger_->info("{}", msg);
    }
  }

  void shutdownImpl() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!logger_) {
      return;
    }

    logger_->flush();
    spdlog::drop("sstd");
    logger_.reset();
    spdlog::shutdown();
  }
};

} // namespace SST

#endif // LOGGER_HPP

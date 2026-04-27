#ifndef FILEDESCRIPTOR_HPP
#define FILEDESCRIPTOR_HPP

#include <unistd.h>

namespace SST {
class FD {
public:
  explicit FD(int fd = -1) : fd_(fd) {}
  ~FD() // 소멸자에서 close를 호출 하여 파일 디스크립터 관리 (RAII)
  {
    if (fd_ >= 0)
      close(fd_);
  }

  // 복사 금지(생성하면서 소유권 복사 및, = 연산자를 통한 복사 방지)
  // 이유는 복사를 허용하게 될 경우 하나의 FD를 다수의 인스턴스가 사용하게됨
  FD(const FD &) = delete;
  FD &operator=(const FD &) = delete;

  // 이동 허용
  FD(FD &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

  FD &operator=(FD &&other) noexcept {
    if (this != &other) { // 자기 자신을 이동 할 경우( 셀프 이동) 방지
      if (fd_ >= 0)
        close(fd_);
      fd_ = other.fd_;
      other.fd_ = -1;
    }
    return *this;
  }

  int get() const { return fd_; } // fd getter
  int release() { // fd를 반환 하고, 소유권을 잃음 (fd 를 다른데서 사용하고
                  // 싶을때)
    int tmp = fd_;
    fd_ = -1;
    return tmp;
  }

private:
  int fd_;
};
} // namespace SST

#endif // FILEDESCRIPTOR_HPP
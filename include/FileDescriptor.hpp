#ifndef FILEDESCRIPTOR_HPP
#define FILEDESCRIPTOR_HPP

#include <unistd.h>

namespace SST
{
    class FD
    {
    public:
        explicit FD(int fd = -1) : fd_(fd) {}
        ~FD()
        {
            if (fd_ >= 0)
                close(fd_);
        }

        // 복사 금지
        FD(const FD &) = delete;
        FD &operator=(const FD &) = delete;

        // 이동 허용
        FD(FD &&other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

        FD &operator=(FD &&other) noexcept
        {
            if (this != &other)
            {
                if (fd_ >= 0)
                    close(fd_);
                fd_ = other.fd_;
                other.fd_ = -1;
            }
            return *this;
        }

        int get() const { return fd_; }
        int release()
        {
            int tmp = fd_;
            fd_ = -1;
            return tmp;
        }

    private:
        int fd_;
    };
}

#endif // FILEDESCRIPTOR_HPP
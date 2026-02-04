#ifndef CIRCULARBUFFER_HPP
#define CIRCULARBUFFER_HPP

#include <vector>
#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace SST {

    class CircularBuffer {
    public:
        explicit CircularBuffer(size_t capacity) 
            : buffer_(capacity), head_(0), tail_(0), size_(0) {}

        // 데이터 추가 (Write)
        bool write(const uint8_t* data, size_t len) {
            if (freeSpace() < len) {
                return false; // 공간 부족
            }

            size_t capacity = buffer_.size();
            size_t first_chunk = std::min(len, capacity - tail_);
            std::memcpy(&buffer_[tail_], data, first_chunk);
            
            if (len > first_chunk) {
                std::memcpy(&buffer_[0], data + first_chunk, len - first_chunk);
            }

            tail_ = (tail_ + len) % capacity;
            size_ += len;
            return true;
        }

        // 데이터 읽기 (Peek - 제거하지 않음)
        bool peek(uint8_t* out_data, size_t len) const {
            if (size_ < len) {
                return false;
            }

            size_t capacity = buffer_.size();
            size_t first_chunk = std::min(len, capacity - head_);
            if(out_data){
                std::memcpy(out_data, &buffer_[head_], first_chunk);
                if (len > first_chunk) {
                    std::memcpy(out_data + first_chunk, &buffer_[0], len - first_chunk);
                }
            }
            return true;
        }

        // 데이터 삭제 (Consume)
        bool consume(size_t len) {
            if (size_ < len) {
                return false;
            }
            head_ = (head_ + len) % buffer_.size();
            size_ -= len;
            return true;
        }

        // 데이터 읽기 및 삭제
        bool read(uint8_t* out_data, size_t len) {
            if (peek(out_data, len)) {
                consume(len);
                return true;
            }
            return false;
        }

        size_t size() const { return size_; }
        size_t capacity() const { return buffer_.size(); }
        size_t freeSpace() const { return buffer_.size() - size_; }
        bool empty() const { return size_ == 0; }
        
        // 연속된 메모리 포인터 반환 (가능한 경우) -> 벡터 변환용
        // 링버퍼 특성상 항상 연속적이지 않으므로, 필요한 경우 임시 벡터를 반환하거나 복사가 필요할 수 있음
        // 여기서는 편의를 위해 전체 데이터를 벡터로 반환하는 헬퍼 추가
        std::vector<uint8_t> toVector() const {
            std::vector<uint8_t> res(size_);
            peek(res.data(), size_);
            return res;
        }

    private:
        std::vector<uint8_t> buffer_;
        size_t head_; // Read Index
        size_t tail_; // Write Index
        size_t size_; // Current Data Size
    };

}

#endif // CIRCULARBUFFER_HPP

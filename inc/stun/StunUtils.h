#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
#ifndef htonll
#define htonll(val)                                          \
  ((((uint64_t)htonl((uint32_t)((val)&0xFFFFFFFF))) << 32) | \
   htonl((uint32_t)((val) >> 32)))
#define ntohll(val)                                          \
  ((((uint64_t)ntohl((uint32_t)((val)&0xFFFFFFFF))) << 32) | \
   ntohl((uint32_t)((val) >> 32)))
#endif

namespace stun {
std::string dumphex(const uint8_t* data, size_t len);

class StunException : public std::runtime_error {
 public:
  // 使用父类的构造函数初始化
  explicit StunException(const std::string& message)
      : std::runtime_error(message) {}
};

}  // namespace stun
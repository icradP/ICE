#include "stun/Stun.h"
#include <variant>
#include <optional>
#include <iostream>

namespace ICE {
struct Connnected {
  /* data */
};

struct Closed {
  /* data */
};

using ICEState = std::variant<Connnected, Closed>;


//处理执行逻辑
class IceSession {
 private:
  /* data */
 public:
  IceSession(/* args */);
  ~IceSession();
  //执行事件循环 异步
  void runOploop();
  //注册回调
  
};

IceSession::IceSession(/* args */) {}
IceSession::~IceSession() {}

}  // namespace ICE

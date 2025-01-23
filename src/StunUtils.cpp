#include "stun/StunUtils.h"
#include <sstream>
#include <iomanip>
using namespace std;
namespace stun {
std::string dumphex(const uint8_t *data, size_t len) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        // 将每个字节转换为16进制表示，并确保两位宽度，不足补0
        hexStream << std::setw(2) << static_cast<int>(data[i]);
    }
    return hexStream.str();
}
}
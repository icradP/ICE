#include "stun/StunAttribute.h"

#include <arpa/inet.h>

#include <sstream>

#include "stun/StunUtils.h"

namespace stun {

std::string AttributeValueStrVisitor::operator()(
    const std::string& value) const {
  return value;
}
std::string AttributeValueStrVisitor::operator()(uint32_t value) const {
  return std::to_string(value);
}
std::string AttributeValueStrVisitor::operator()(uint64_t value) const {
  return std::to_string(value);
}
std::string AttributeValueStrVisitor::operator()(uint16_t value) const {
  return std::to_string(value);
}
std::string AttributeValueStrVisitor::operator()(uint8_t value) const {
  return std::to_string(static_cast<uint32_t>(value));
}
std::string AttributeValueStrVisitor::operator()(
    const std::pair<std::string, uint16_t>& value) const {
  return value.first + ":" + std::to_string(value.second);
}
std::string AttributeValueStrVisitor::operator()(
    const std::vector<uint8_t>& value) const {
  return dumphex(value.data(), value.size());
}
std::string AttributeValueStrVisitor::operator()(
    const StunMessageErrorCode& value) const {
  std::ostringstream oss;
  oss << static_cast<int>(getStunMessageErrCodeEnum(value));
  if (!value.err_reason.empty()) {
    oss << "(" << std::string(value.err_reason.begin(), value.err_reason.end())
        << ")";
  }
  return oss.str();
}
std::string AttributeValueStrVisitor::operator()(const std::monostate&) const {
  return "EMPTY";
}

const std::string_view ProtocolTransportEnum2str(ProtocolTransport num) {
  switch (num) {
    case TCP:
      return "TCP";
    case UDP:
      return "UDP";
    default:
      return "ERROR-NUM";
  }
}
std::string AttributeType2str(AttributeType type) {
  auto it = attributeTypeMap.find(type);
  if (it != attributeTypeMap.end()) {
    return it->second;
  }
  return "UNKNOWN";
}
std::string AttributeValue2str(const AttributeValue& attrvalue) {
  return std::visit(AttributeValueStrVisitor{}, attrvalue);
}

std::vector<uint8_t> makeRequestTransport(ProtocolTransport num) {
  std::vector<uint8_t> test(4, 0);
  test[0] = num;
  return test;
}

ProtocolTransport parseRequestTransport(std::vector<uint8_t> test) {
  return static_cast<ProtocolTransport>(test[0]);
}

std::string StunMessageErrCodeEnum2str(StunMessageErrCodeEnum code) {
  auto it = stunMessageErrCodeEnumMap.find(static_cast<int>(code));
  if (it != stunMessageErrCodeEnumMap.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

std::vector<uint8_t> StunMessageErrCodeEnum2value(StunMessageErrCodeEnum code) {
  auto it = stunMessageErrCodeEnumMap.find(static_cast<int>(code));
  if (it != stunMessageErrCodeEnumMap.end()) {
    return std::vector<uint8_t>(it->second.begin(), it->second.end());
  }
  std::string unknown = "UNKNOWN";
  return std::vector<uint8_t>(unknown.begin(), unknown.end());
}

StunMessageErrorCode makeStunMessageErrorCode(StunMessageErrCodeEnum code) {
  StunMessageErrorCode error;
  error.reserved = 0;  // default = 0
  error.err_class = static_cast<uint8_t>(static_cast<int>(code) / 100);
  error.err_code = static_cast<uint8_t>(static_cast<int>(code) % 100);
  error.err_reason = StunMessageErrCodeEnum2value(code);
  return error;
}

StunMessageErrorCode makeStunMessageErrorCode(const uint8_t* data, size_t len) {
  if (len < 4) {
    throw StunException("Invalid STUN error message");
  }
  StunMessageErrorCode error;
  error.reserved = ntohs(*reinterpret_cast<const uint16_t*>(data));
  error.err_class = data[2];
  error.err_code = data[3];
  if (len > 4) {
    error.err_reason.assign(data + 4, data + len);
  }
  return error;
}

std::vector<uint8_t> serializeStunMessageErrorCode(
    const StunMessageErrorCode& error) {
  std::vector<uint8_t> data;
  uint16_t reservedNetworkOrder = htons(error.reserved);
  data.insert(data.end(), reinterpret_cast<uint8_t*>(&reservedNetworkOrder),
              reinterpret_cast<uint8_t*>(&reservedNetworkOrder) +
                  sizeof(reservedNetworkOrder));
  data.push_back(error.err_class);
  data.push_back(error.err_code);
  data.insert(data.end(), error.err_reason.begin(), error.err_reason.end());
  return data;
}

StunMessageErrCodeEnum getStunMessageErrCodeEnum(
    const StunMessageErrorCode& error) {
  return static_cast<StunMessageErrCodeEnum>(error.err_class * 100 +
                                             error.err_code);
}

std::vector<StunAttribute> makeAttributes(const uint8_t* data, size_t length) {
  std::vector<StunAttribute> attributes;
  size_t offset = 0;
  while (offset + 4 <= length) {
    StunAttribute attr = deserialize(data + offset, length - offset);
    attributes.push_back(std::move(attr));
    offset += 4 + attr.length;
  }
  return attributes;
}

std::vector<uint8_t> makeIpPortVector(const std::string& ip, uint16_t port,
                                      bool isXor) {
  std::vector<uint8_t> result;
  sockaddr_storage addr;
  socklen_t addr_len = sizeof(addr);
  if (inet_pton(AF_INET, ip.c_str(), &(((sockaddr_in*)&addr)->sin_addr))) {
    addr.ss_family = AF_INET;
    ((sockaddr_in*)&addr)->sin_port = htons(port);
    result.resize(8);
    result[1] = 1;  // IPv4
    memcpy(result.data() + 2, &((sockaddr_in*)&addr)->sin_port, 2);
    memcpy(result.data() + 4, &((sockaddr_in*)&addr)->sin_addr, 4);
  } else if (inet_pton(AF_INET6, ip.c_str(),
                       &(((sockaddr_in6*)&addr)->sin6_addr))) {
    addr.ss_family = AF_INET6;
    ((sockaddr_in6*)&addr)->sin6_port = htons(port);
    result.resize(20);
    result[1] = 2;  // IPv6
    memcpy(result.data() + 2, &((sockaddr_in6*)&addr)->sin6_port, 2);
    memcpy(result.data() + 4, &((sockaddr_in6*)&addr)->sin6_addr, 16);
  } else {
    throw StunException("Invalid IP address: " + ip);
  }

  if (isXor) {
    uint16_t* portPtr = reinterpret_cast<uint16_t*>(result.data() + 2);
    *portPtr = htons(ntohs(*portPtr) ^ 0x2112);
    if (result[1] == 1) {  // IPv4
      uint32_t* addrPtr = reinterpret_cast<uint32_t*>(result.data() + 4);
      *addrPtr = htonl(ntohl(*addrPtr) ^ 0x2112A442);
    } else if (result[1] == 2) {  // IPv6
      for (int i = 0; i < 16; ++i) {
        result[4 + i] ^= magicCookie[i % 4];
      }
    }
  }
  return result;
}

AttributeValue parseAttribute2Variant(const StunAttribute& attr) {
  auto it = attributeValueTypeMap.find(attr.type);
  if (it == attributeValueTypeMap.end()) {
    throw StunException("Unknown attribute type");
  }

  switch (it->second) {
    case AttributeValueType::STRING:
      return std::string(attr.value.begin(), attr.value.end());
    case AttributeValueType::UINT32:
      if (attr.value.size() != 4) throw StunException("Invalid UINT32 size");
      return ntohl(*reinterpret_cast<const uint32_t*>(attr.value.data()));
    case AttributeValueType::UINT64:
      if (attr.value.size() != 8) throw StunException("Invalid UINT64 size");
      return ntohll(*reinterpret_cast<const uint64_t*>(attr.value.data()));
    case AttributeValueType::UINT16:
      if (attr.value.size() != 2) throw StunException("Invalid UINT16 size");
      return ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data()));
    case AttributeValueType::UINT8:
      if (attr.value.size() != 1) throw StunException("Invalid UINT8 size");
      return attr.value[0];
    case AttributeValueType::SOCKADDR: {
      if (attr.value.size() < 4) throw StunException("Invalid SOCKADDR size");
      char ip[INET6_ADDRSTRLEN];
      uint16_t port;
      if (attr.value[1] == 1) {  // IPv4
        struct sockaddr_in addr;
        memcpy(&addr.sin_addr, attr.value.data() + 4, 4);
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        port = ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data() + 2));
      } else if (attr.value[1] == 2) {  // IPv6
        struct sockaddr_in6 addr;
        memcpy(&addr.sin6_addr, attr.value.data() + 4, 16);
        inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
        port = ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data() + 2));
      } else {
        throw StunException("Unknown address family");
      }
      return std::make_pair(std::string(ip), port);
    }
    case AttributeValueType::BINARY:
      return attr.value;
    case AttributeValueType::SPECIAL:
      if (attr.type == AttributeType::FINGERPRINT)
        return std::string("FINGERPRINT");
      else if (attr.type == AttributeType::MESSAGE_INTEGRITY)
        return std::string("MESSAGE_INTEGRITY");
      else if (attr.type == AttributeType::UNKNOWN_ATTRIBUTES)
        return std::string("UNKNOWN_ATTRIBUTES");
      else if (attr.type == AttributeType::ERROR_CODE) {
        StunMessageErrorCode code =
            makeStunMessageErrorCode(attr.value.data(), attr.value.size());
        return code;
      } else
        return std::string("SPECIAL");
    case AttributeValueType::EMPTY:
      return std::monostate{};
    default:
      throw StunException("Unknown attribute value type");
  }
}

std::pair<std::string, uint16_t> getXorAddr(const StunAttribute& attr) {
  char ip[INET6_ADDRSTRLEN];
  uint16_t port;
  if (attr.type == AttributeType::XOR_MAPPED_ADDRESS ||
      attr.type == AttributeType::XOR_PEER_ADDRESS ||
      attr.type == AttributeType::XOR_RELAYED_ADDRESS) {
    uint16_t xorPort =
        ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data() + 2)) ^
        0x2112;
    if (attr.value[1] == 1) {  // IPv4
      struct sockaddr_in addr;
      uint32_t xorAddr;
      memcpy(&xorAddr, attr.value.data() + 4, 4);
      xorAddr ^= ntohl(0x2112A442);
      memcpy(&addr.sin_addr, &xorAddr, 4);
      inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
      port = xorPort;
    } else if (attr.value[1] == 2) {  // IPv6
      struct sockaddr_in6 addr;
      uint8_t xorAddr[16];
      memcpy(xorAddr, attr.value.data() + 4, 16);
      for (int i = 0; i < 16; ++i) {
        xorAddr[i] ^= magicCookie[i % 4];
      }
      memcpy(&addr.sin6_addr, xorAddr, 16);
      inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
      port = xorPort;
    } else {
      throw StunException("Unknown address family");
    }
  } else {
    throw StunException("Not XOR address");
  }
  return std::make_pair(std::string(ip), port);
}

std::pair<std::string, uint16_t> getAddr(const StunAttribute& attr) {
  char ip[INET6_ADDRSTRLEN];
  uint16_t port;
  uint16_t xorPort =
      ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data() + 2));
  if (attr.value[1] == 1) {  // IPv4
    struct sockaddr_in addr;
    uint32_t xorAddr;
    memcpy(&xorAddr, attr.value.data() + 4, 4);
    memcpy(&addr.sin_addr, &xorAddr, 4);
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    port = xorPort;
  } else if (attr.value[1] == 2) {  // IPv6
    struct sockaddr_in6 addr;
    uint8_t xorAddr[16];
    memcpy(xorAddr, attr.value.data() + 4, 16);
    memcpy(&addr.sin6_addr, xorAddr, 16);
    inet_ntop(AF_INET6, &addr.sin6_addr, ip, sizeof(ip));
    port = xorPort;
  } else {
    throw StunException("Unknown address family");
  }
  return std::make_pair(std::string(ip), port);
}

StunAttribute::StunAttribute(AttributeType type, std::vector<uint8_t> value,
                             uint16_t padding)
    : type(type),
      length(static_cast<uint16_t>(value.size())),
      value(std::move(value)),
      padding(padding) {}

StunAttribute::StunAttribute(AttributeType type, const char* value,
                             uint16_t padding)
    : type(type),
      length(static_cast<uint16_t>(std::strlen(value))),
      value(reinterpret_cast<const uint8_t*>(value),
            reinterpret_cast<const uint8_t*>(value) + std::strlen(value)),
      padding(padding) {
  this->value.assign(
      reinterpret_cast<const uint8_t*>(value),
      reinterpret_cast<const uint8_t*>(value) + std::strlen(value));
}

StunAttribute::StunAttribute(AttributeType type,
                             const StunMessageErrorCode& value)
    : type(type), padding(0) {
  this->value = serializeStunMessageErrorCode(value);
  this->length = static_cast<uint16_t>(this->value.size());
}
StunAttribute::StunAttribute(AttributeType type, const uint8_t* value,
                             size_t size)
    : type(type), padding(0), length(size) {
  this->value.assign(value, value + size);
}

StunAttribute::StunAttribute::StunAttribute(AttributeType type, uint32_t num,
                                            uint16_t padding)
    : type(type),
      length(static_cast<uint16_t>(sizeof(uint32_t))),
      value(),
      padding(padding) {
  uint32_t networkOrderNum = htonl(num);
  value.assign(
      reinterpret_cast<uint8_t*>(&networkOrderNum),
      reinterpret_cast<uint8_t*>(&networkOrderNum) + sizeof(networkOrderNum));
}

std::vector<uint8_t> StunAttribute::serialize() const {
  std::vector<uint8_t> result;
  uint16_t typeNetworkOrder = htons(static_cast<uint16_t>(type));
  uint16_t lengthNetworkOrder = htons(length);
  result.insert(
      result.end(), reinterpret_cast<uint8_t*>(&typeNetworkOrder),
      reinterpret_cast<uint8_t*>(&typeNetworkOrder) + sizeof(typeNetworkOrder));
  result.insert(result.end(), reinterpret_cast<uint8_t*>(&lengthNetworkOrder),
                reinterpret_cast<uint8_t*>(&lengthNetworkOrder) +
                    sizeof(lengthNetworkOrder));
  result.insert(result.end(), value.begin(), value.end());
  return result;
}

StunAttribute deserialize(const uint8_t* data, size_t length) {
  if (length < 4) {
    throw StunException("Buffer too small for STUN attribute");
  }
  AttributeType type = static_cast<AttributeType>(
      ntohs(*reinterpret_cast<const uint16_t*>(data)));
  uint16_t attrLength = ntohs(*reinterpret_cast<const uint16_t*>(data + 2));
  // Adjust length to account for padding
  uint16_t padding = 0;
  if (attrLength % 4 != 0) {
    padding = 4 - (attrLength % 4);
    attrLength += padding;
  }
  if (length < 4 + attrLength) {
    std::ostringstream oss;
    //   oss << "Buffer too small for STUN attribute value: Attribute type("
    //       << dumphex(data, sizeof(uint16_t)) << "):" <<
    //       AttributeType2str(type);
    throw StunException(oss.str());
  }
  std::vector<uint8_t> value(data + 4, data + 4 + attrLength);
  return StunAttribute(type, std::move(value), padding);
}

}  // namespace stun

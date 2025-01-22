#ifndef STUN_HPP
#define STUN_HPP

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>
static std::string dumphex(const uint8_t* data, size_t len) {
  using namespace std;
  string ret;
  for (size_t i = 0; i < len; ++i) {
    char buf[3];
    snprintf(buf, sizeof(buf), "%.2X", data[i]);
    ret += buf;
  }
  return ret;
}

#ifndef htonll
#define htonll(val)                                          \
  ((((uint64_t)htonl((uint32_t)((val)&0xFFFFFFFF))) << 32) | \
   htonl((uint32_t)((val) >> 32)))
#define ntohll(val)                                          \
  ((((uint64_t)ntohl((uint32_t)((val)&0xFFFFFFFF))) << 32) | \
   ntohl((uint32_t)((val) >> 32)))
#endif

namespace stun {
enum class AttributeType : uint16_t {
  MAPPED_ADDRESS = 0x0001,
  RESPONSE_ADDRESS = 0x0002,
  CHANGE_REQUEST = 0x0003,
  SOURCE_ADDRESS = 0x0004,
  CHANGED_ADDRESS = 0x0005,
  USERNAME = 0x0006,
  PASSWORD = 0x0007,
  MESSAGE_INTEGRITY = 0x0008,
  ERROR_CODE = 0x0009,
  UNKNOWN_ATTRIBUTES = 0x000A,
  REFLECTED_FROM = 0x000B,
  CHANNEL_NUMBER = 0x000C,
  LIFETIME = 0x000D,
  BANDWIDTH = 0x000E,
  XOR_PEER_ADDRESS = 0x000F,
  DATA = 0x0010,
  REALM = 0x0014,
  NONCE = 0x0015,
  XOR_RELAYED_ADDRESS = 0x0016,
  REQ_ADDRESS_FAMILY = 0x0017,
  EVEN_PORT = 0x0018,
  REQUESTED_TRANSPORT = 0x0019,
  DONT_FRAGMENT = 0x001A,
  XOR_MAPPED_ADDRESS = 0x0020,
  TIMER_VAL = 0x0021,
  RESERVATION_TOKEN = 0x0022,
  PRIORITY = 0x0024,
  USE_CANDIDATE = 0x0025,
  PADDING = 0x0026,
  RESPONSE_PORT = 0x0027,
  CONNECTION_ID = 0x0028,
  SOFTWARE = 0x8022,
  ALTERNATE_SERVER = 0x8023,
  FINGERPRINT = 0x8028,
  ICE_CONTROLLED = 0x8029,
  ICE_CONTROLLING = 0x802A,
  RESPONSE_ORIGIN = 0x802B,
  OTHER_ADDRESS = 0x802C,
};
enum class StunMessageErrCodeEnum {
  TRY_ALTERNATE = 300,
  BAD_REQUEST = 400,
  UNAUTHORIZED = 401,
  UNKNOWN_ATTRIBUTE = 420,
  STALE_NONCE = 438,
  SERVER_ERROR = 500,
  GLOBAL_FAILURE = 600,
  FORBIDDEN = 403,
  ALLOCATION_MISMATCH = 437,
  ADDR_FAMILY_NOT_SUPP = 440,
  WRONG_CREDENTIALS = 441,
  UNSUPP_TRANSPORT_PROTO = 442,
  PEER_ADD_FAMILY_MISMATCH = 443,
  CONNECTION_ALREADY_EXISTS = 446,
  CONNECTION_FAILURE = 447,
  ALLOCATION_QUOTA_REACHED = 486,
  ROLE_CONFLICT = 487,
  INSUFFICIENT_CAPACITY = 508,
};
static const std::unordered_map<int, std::string> stunMessageErrCodeEnumMap = {
  {300, "Try Alternate"},
  {400, "Bad Request"},
  {401, "Unauthorized"},
  {403, "Forbidden"},
  {420, "Unknown Attribute"},
  {437, "Allocation Mismatch"},
  {438, "Stale Nonce"},
  {440, "Address Family Not Supported"},
  {441, "Wrong Credentials"},
  {442, "Unsupported Transport Protocol"},
  {443, "Peer Address Family Mismatch"},
  {446, "Connection Already Exists"},
  {447, "Connection Failure"},
  {486, "Allocation Quota Reached"},
  {487, "Role Conflict"},
  {500, "Server Error"},
  {508, "Insufficient Capacity"},
  {600, "Global Failure"},
};


static std::string StunMessageErrCodeEnum2str(StunMessageErrCodeEnum code) {
  auto it = stunMessageErrCodeEnumMap.find(static_cast<int>(code));
  if (it != stunMessageErrCodeEnumMap.end()) {
  return it->second;
  }
  return "UNKNOWN";
}
static std::vector<uint8_t> StunMessageErrCodeEnum2value(StunMessageErrCodeEnum code) {
  auto it = stunMessageErrCodeEnumMap.find(static_cast<int>(code));
  if (it != stunMessageErrCodeEnumMap.end()) {
    return std::vector<uint8_t>(it->second.begin(), it->second.end());
  }
  std::string unknown = "UNKNOWN";
  return std::vector<uint8_t>(unknown.begin(), unknown.end());
}

struct StunMessageErrorCode;
static StunMessageErrorCode makeStunMessageErrorCode(StunMessageErrCodeEnum code);

struct StunMessageErrorCode {
  uint16_t reserved;
  uint8_t err_class; /* code / 100 */
  uint8_t err_code;  /* code % 100 */
  std::vector<uint8_t> err_reason;
};


static StunMessageErrorCode makeStunMessageErrorCode(StunMessageErrCodeEnum code) {


  StunMessageErrorCode error;
  error.reserved = 0; // default = 0
  error.err_class = static_cast<uint8_t>(static_cast<int>(code) / 100);
  error.err_code = static_cast<uint8_t>(static_cast<int>(code) % 100);
  error.err_reason = StunMessageErrCodeEnum2value(code);
  return error;
}
static StunMessageErrorCode makeStunMessageErrorCode(const uint8_t* data,
                           size_t len) {
  if (len < 4) {
  throw std::runtime_error("Invalid STUN error message");
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

static std::vector<uint8_t> serializeStunMessageErrorCode(const StunMessageErrorCode& error) {
  std::vector<uint8_t> data;
  uint16_t reservedNetworkOrder = htons(error.reserved);
  data.insert(data.end(), reinterpret_cast<uint8_t*>(&reservedNetworkOrder),
        reinterpret_cast<uint8_t*>(&reservedNetworkOrder) + sizeof(reservedNetworkOrder));
  data.push_back(error.err_class);
  data.push_back(error.err_code);
  data.insert(data.end(), error.err_reason.begin(), error.err_reason.end());
  return data;
}

static StunMessageErrCodeEnum getStunMessageErrCodeEnum(
    const StunMessageErrorCode& error) {
  return static_cast<StunMessageErrCodeEnum>(error.err_class * 100 +
                                             error.err_code);
}

enum class AttributeValueType {
  STRING,
  UINT32,
  UINT64,
  UINT16,
  UINT8,
  SOCKADDR,
  BINARY,
  SPECIAL,
  EMPTY
};

static const std::unordered_map<AttributeType, AttributeValueType>
    attributeValueTypeMap = {
        {AttributeType::MAPPED_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::RESPONSE_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::CHANGE_REQUEST, AttributeValueType::UINT32},
        {AttributeType::SOURCE_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::CHANGED_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::USERNAME, AttributeValueType::STRING},
        {AttributeType::PASSWORD, AttributeValueType::STRING},
        {AttributeType::MESSAGE_INTEGRITY, AttributeValueType::SPECIAL},
        {AttributeType::ERROR_CODE, AttributeValueType::SPECIAL},
        {AttributeType::UNKNOWN_ATTRIBUTES, AttributeValueType::SPECIAL},
        {AttributeType::REFLECTED_FROM, AttributeValueType::SOCKADDR},
        {AttributeType::CHANNEL_NUMBER, AttributeValueType::UINT32},
        {AttributeType::LIFETIME, AttributeValueType::UINT32},
        {AttributeType::BANDWIDTH, AttributeValueType::UINT32},
        {AttributeType::XOR_PEER_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::DATA, AttributeValueType::BINARY},
        {AttributeType::REALM, AttributeValueType::STRING},
        {AttributeType::NONCE, AttributeValueType::STRING},
        {AttributeType::XOR_RELAYED_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::REQ_ADDRESS_FAMILY, AttributeValueType::UINT8},
        {AttributeType::EVEN_PORT, AttributeValueType::UINT8},
        {AttributeType::REQUESTED_TRANSPORT, AttributeValueType::UINT32},
        {AttributeType::DONT_FRAGMENT, AttributeValueType::EMPTY},
        {AttributeType::XOR_MAPPED_ADDRESS, AttributeValueType::SOCKADDR},
        {AttributeType::TIMER_VAL, AttributeValueType::UINT32},
        {AttributeType::RESERVATION_TOKEN, AttributeValueType::UINT64},
        {AttributeType::PRIORITY, AttributeValueType::UINT32},
        {AttributeType::USE_CANDIDATE, AttributeValueType::EMPTY},
        {AttributeType::PADDING, AttributeValueType::BINARY},
        {AttributeType::RESPONSE_PORT, AttributeValueType::UINT16},
        {AttributeType::CONNECTION_ID, AttributeValueType::UINT32},
        {AttributeType::SOFTWARE, AttributeValueType::STRING},
        {AttributeType::ALTERNATE_SERVER, AttributeValueType::SOCKADDR},
        {AttributeType::FINGERPRINT, AttributeValueType::SPECIAL},
        {AttributeType::ICE_CONTROLLED, AttributeValueType::UINT64},
        {AttributeType::ICE_CONTROLLING, AttributeValueType::UINT64},
        {AttributeType::RESPONSE_ORIGIN, AttributeValueType::SOCKADDR},
        {AttributeType::OTHER_ADDRESS, AttributeValueType::SOCKADDR},
};

static const std::unordered_map<AttributeType, std::string> attributeTypeMap = {
    {AttributeType::MAPPED_ADDRESS, "MAPPED_ADDRESS"},
    {AttributeType::RESPONSE_ADDRESS, "RESPONSE_ADDRESS"},
    {AttributeType::CHANGE_REQUEST, "CHANGE_REQUEST"},
    {AttributeType::SOURCE_ADDRESS, "SOURCE_ADDRESS"},
    {AttributeType::CHANGED_ADDRESS, "CHANGED_ADDRESS"},
    {AttributeType::USERNAME, "USERNAME"},
    {AttributeType::PASSWORD, "PASSWORD"},
    {AttributeType::MESSAGE_INTEGRITY, "MESSAGE_INTEGRITY"},
    {AttributeType::ERROR_CODE, "ERROR_CODE"},
    {AttributeType::UNKNOWN_ATTRIBUTES, "UNKNOWN_ATTRIBUTES"},
    {AttributeType::REFLECTED_FROM, "REFLECTED_FROM"},
    {AttributeType::CHANNEL_NUMBER, "CHANNEL_NUMBER"},
    {AttributeType::LIFETIME, "LIFETIME"},
    {AttributeType::BANDWIDTH, "BANDWIDTH"},
    {AttributeType::XOR_PEER_ADDRESS, "XOR_PEER_ADDRESS"},
    {AttributeType::DATA, "DATA"},
    {AttributeType::REALM, "REALM"},
    {AttributeType::NONCE, "NONCE"},
    {AttributeType::XOR_RELAYED_ADDRESS, "XOR_RELAYED_ADDRESS"},
    {AttributeType::REQ_ADDRESS_FAMILY, "REQ_ADDRESS_FAMILY"},
    {AttributeType::EVEN_PORT, "EVEN_PORT"},
    {AttributeType::REQUESTED_TRANSPORT, "REQUESTED_TRANSPORT"},
    {AttributeType::DONT_FRAGMENT, "DONT_FRAGMENT"},
    {AttributeType::XOR_MAPPED_ADDRESS, "XOR_MAPPED_ADDRESS"},
    {AttributeType::TIMER_VAL, "TIMER_VAL"},
    {AttributeType::RESERVATION_TOKEN, "RESERVATION_TOKEN"},
    {AttributeType::PRIORITY, "PRIORITY"},
    {AttributeType::USE_CANDIDATE, "USE_CANDIDATE"},
    {AttributeType::PADDING, "PADDING"},
    {AttributeType::RESPONSE_PORT, "RESPONSE_PORT"},
    {AttributeType::CONNECTION_ID, "CONNECTION_ID"},
    {AttributeType::SOFTWARE, "SOFTWARE"},
    {AttributeType::ALTERNATE_SERVER, "ALTERNATE_SERVER"},
    {AttributeType::FINGERPRINT, "FINGERPRINT"},
    {AttributeType::ICE_CONTROLLED, "ICE_CONTROLLED"},
    {AttributeType::ICE_CONTROLLING, "ICE_CONTROLLING"},
    {AttributeType::RESPONSE_ORIGIN, "RESPONSE_ORIGIN"},
    {AttributeType::OTHER_ADDRESS, "OTHER_ADDRESS"},
};

enum class MessageType : uint16_t {
  BINDING_REQUEST = 0x0001,
  BINDING_RESPONSE = 0x0101,
  BINDING_ERROR_RESPONSE = 0x0111,
  BINDING_INDICATION = 0x0011,
  SHARED_SECRET_REQUEST = 0x0002,
  SHARED_SECRET_RESPONSE = 0x0102,
  SHARED_SECRET_ERROR_RESPONSE = 0x0112,
  ALLOCATE_REQUEST = 0x0003,
  ALLOCATE_RESPONSE = 0x0103,
  ALLOCATE_ERROR_RESPONSE = 0x0113,
  REFRESH_REQUEST = 0x0004,
  REFRESH_RESPONSE = 0x0104,
  REFRESH_ERROR_RESPONSE = 0x0114,
  SEND_INDICATION = 0x0016,
  DATA_INDICATION = 0x0017,
  CREATE_PERM_REQUEST = 0x0008,
  CREATE_PERM_RESPONSE = 0x0108,
  CREATE_PERM_ERROR_RESPONSE = 0x0118,
  CHANNEL_BIND_REQUEST = 0x0009,
  CHANNEL_BIND_RESPONSE = 0x0109,
  CHANNEL_BIND_ERROR_RESPONSE = 0x0119,
  CONNECT_REQUEST = 0x000A,
  CONNECT_RESPONSE = 0x010A,
  CONNECT_ERROR_RESPONSE = 0x011A,
  CONNECTION_BIND_REQUEST = 0x000B,
  CONNECTION_BIND_RESPONSE = 0x010B,
  CONNECTION_BIND_ERROR_RESPONSE = 0x011B,
  CONNECTION_ATTEMPT_REQUEST = 0x000C,
  CONNECTION_ATTEMPT_RESPONSE = 0x010C,
  CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C
};

static const std::unordered_map<MessageType, std::string> messageTypeMap = {
    {MessageType::BINDING_REQUEST, "BINDING_REQUEST"},
    {MessageType::BINDING_RESPONSE, "BINDING_RESPONSE"},
    {MessageType::BINDING_ERROR_RESPONSE, "BINDING_ERROR_RESPONSE"},
    {MessageType::BINDING_INDICATION, "BINDING_INDICATION"},
    {MessageType::SHARED_SECRET_REQUEST, "SHARED_SECRET_REQUEST"},
    {MessageType::SHARED_SECRET_RESPONSE, "SHARED_SECRET_RESPONSE"},
    {MessageType::SHARED_SECRET_ERROR_RESPONSE, "SHARED_SECRET_ERROR_RESPONSE"},
    {MessageType::ALLOCATE_REQUEST, "ALLOCATE_REQUEST"},
    {MessageType::ALLOCATE_RESPONSE, "ALLOCATE_RESPONSE"},
    {MessageType::ALLOCATE_ERROR_RESPONSE, "ALLOCATE_ERROR_RESPONSE"},
    {MessageType::REFRESH_REQUEST, "REFRESH_REQUEST"},
    {MessageType::REFRESH_RESPONSE, "REFRESH_RESPONSE"},
    {MessageType::REFRESH_ERROR_RESPONSE, "REFRESH_ERROR_RESPONSE"},
    {MessageType::SEND_INDICATION, "SEND_INDICATION"},
    {MessageType::DATA_INDICATION, "DATA_INDICATION"},
    {MessageType::CREATE_PERM_REQUEST, "CREATE_PERM_REQUEST"},
    {MessageType::CREATE_PERM_RESPONSE, "CREATE_PERM_RESPONSE"},
    {MessageType::CREATE_PERM_ERROR_RESPONSE, "CREATE_PERM_ERROR_RESPONSE"},
    {MessageType::CHANNEL_BIND_REQUEST, "CHANNEL_BIND_REQUEST"},
    {MessageType::CHANNEL_BIND_RESPONSE, "CHANNEL_BIND_RESPONSE"},
    {MessageType::CHANNEL_BIND_ERROR_RESPONSE, "CHANNEL_BIND_ERROR_RESPONSE"},
    {MessageType::CONNECT_REQUEST, "CONNECT_REQUEST"},
    {MessageType::CONNECT_RESPONSE, "CONNECT_RESPONSE"},
    {MessageType::CONNECT_ERROR_RESPONSE, "CONNECT_ERROR_RESPONSE"},
    {MessageType::CONNECTION_BIND_REQUEST, "CONNECTION_BIND_REQUEST"},
    {MessageType::CONNECTION_BIND_RESPONSE, "CONNECTION_BIND_RESPONSE"},
    {MessageType::CONNECTION_BIND_ERROR_RESPONSE,
     "CONNECTION_BIND_ERROR_RESPONSE"},
    {MessageType::CONNECTION_ATTEMPT_REQUEST, "CONNECTION_ATTEMPT_REQUEST"},
    {MessageType::CONNECTION_ATTEMPT_RESPONSE, "CONNECTION_ATTEMPT_RESPONSE"},
    {MessageType::CONNECTION_ATTEMPT_ERROR_RESPONSE,
     "CONNECTION_ATTEMPT_ERROR_RESPONSE"}};

std::string static MessageType2str(MessageType type) {
  auto it = messageTypeMap.find(type);
  if (it != messageTypeMap.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

std::string static AttributeType2str(AttributeType type) {
  auto it = attributeTypeMap.find(type);
  if (it != attributeTypeMap.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

struct StunHeader {
  MessageType messageType;
  uint16_t messageLength;
  uint32_t magicCookie;
  uint8_t transactionID[12];
};
constexpr static uint8_t magicCookie[] = {0x21, 0x12, 0xA4, 0x42};

static bool isStunMessage(const uint8_t* data, size_t len) {
  return ((len >= 20) && (data[0] < 3) && (data[4] == magicCookie[0]) &&
          (data[5] == magicCookie[1]) && (data[6] == magicCookie[2]) &&
          (data[7] == magicCookie[3]));
}

using AttributeValue =
    std::variant<std::string, uint32_t, uint64_t, uint16_t, uint8_t,
                 std::pair<std::string, uint16_t>, std::vector<uint8_t>,
                 StunMessageErrorCode, std::monostate>;

struct StunAttribute {
  AttributeType type;
  uint16_t length;
  std::vector<uint8_t> value;
  uint16_t padding = 0;

  StunAttribute(AttributeType type, std::vector<uint8_t> value,
                uint16_t padding = 0)
      : type(type),
        length(static_cast<uint16_t>(value.size())),
        value(std::move(value)),
        padding(padding) {}

  StunAttribute(AttributeType type, const StunMessageErrorCode& value)
      : type(type),
        padding(0) {
          this->value = serializeStunMessageErrorCode(value);
          this->length = static_cast<uint16_t>(this->value.size());
        }
  StunAttribute(AttributeType type, const uint8_t* value, size_t size)
      : type(type),
        padding(0), length(size) {
          this->value.assign(value, value + size);
        }

  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> result;
    uint16_t typeNetworkOrder = htons(static_cast<uint16_t>(type));
    uint16_t lengthNetworkOrder = htons(length);
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&typeNetworkOrder),
                  reinterpret_cast<uint8_t*>(&typeNetworkOrder) +
                      sizeof(typeNetworkOrder));
    result.insert(result.end(), reinterpret_cast<uint8_t*>(&lengthNetworkOrder),
                  reinterpret_cast<uint8_t*>(&lengthNetworkOrder) +
                      sizeof(lengthNetworkOrder));
    result.insert(result.end(), value.begin(), value.end());
    return result;
  }

  static StunAttribute deserialize(const uint8_t* data, size_t length) {
    if (length < 4) {
      throw std::runtime_error("Buffer too small for STUN attribute");
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
      oss << "Buffer too small for STUN attribute value: Attribute type("
          << dumphex(data, sizeof(uint16_t)) << "):" << AttributeType2str(type);
      throw std::runtime_error(oss.str());
    }
    std::vector<uint8_t> value(data + 4, data + 4 + attrLength);
    return StunAttribute(type, std::move(value), padding);
  }
};

std::vector<StunAttribute> makeAttributes(const uint8_t* data, size_t length) {
  std::vector<StunAttribute> attributes;
  size_t offset = 0;
  while (offset + 4 <= length) {
    StunAttribute attr =
        StunAttribute::deserialize(data + offset, length - offset);
    attributes.push_back(std::move(attr));
    offset += 4 + attr.length;
  }
  return attributes;
}

struct AttributeValueStrVisitor {
  std::string operator()(const std::string& value) const { return value; }
  std::string operator()(uint32_t value) const { return std::to_string(value); }
  std::string operator()(uint64_t value) const { return std::to_string(value); }
  std::string operator()(uint16_t value) const { return std::to_string(value); }
  std::string operator()(uint8_t value) const {
    return std::to_string(static_cast<uint32_t>(value));
  }
  std::string operator()(const std::pair<std::string, uint16_t>& value) const {
    return value.first + ":" + std::to_string(value.second);
  }
  std::string operator()(const std::vector<uint8_t>& value) const {
    return dumphex(value.data(), value.size());
  }
  std::string operator()(const StunMessageErrorCode& value) const {
    std::ostringstream oss;
    oss << static_cast<int>(getStunMessageErrCodeEnum(value));
    if (!value.err_reason.empty()) {
      oss << "("
          << std::string(value.err_reason.begin(), value.err_reason.end())
          << ")";
    }
    return oss.str();
  }
  std::string operator()(const std::monostate&) const { return "EMPTY"; }
};

std::string AttributeValue2str(const AttributeValue& attrvalue) {
  return std::visit(AttributeValueStrVisitor{}, attrvalue);
}
// XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS
// xor_addr = addr ^ magic_cookie
// xor_port = port ^ (magic_cookie >> 16)
// RFC 5389 : 15.2 XOR-MAPPED-ADDRESS : avoid middlebox filtering
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
      throw std::runtime_error("Unknown address family");
    }
  } else {
    throw std::runtime_error("Not XOR address");
  }
  return std::make_pair(std::string(ip), port);
}

AttributeValue parseAttribute2Variant(const StunAttribute& attr) {
  auto it = attributeValueTypeMap.find(attr.type);
  if (it == attributeValueTypeMap.end()) {
    throw std::runtime_error("Unknown attribute type");
  }

  switch (it->second) {
    case AttributeValueType::STRING:
      return std::string(attr.value.begin(), attr.value.end());
    case AttributeValueType::UINT32:
      if (attr.value.size() != 4)
        throw std::runtime_error("Invalid UINT32 size");
      return ntohl(*reinterpret_cast<const uint32_t*>(attr.value.data()));
    case AttributeValueType::UINT64:
      if (attr.value.size() != 8)
        throw std::runtime_error("Invalid UINT64 size");
      return ntohll(*reinterpret_cast<const uint64_t*>(attr.value.data()));
    case AttributeValueType::UINT16:
      if (attr.value.size() != 2)
        throw std::runtime_error("Invalid UINT16 size");
      return ntohs(*reinterpret_cast<const uint16_t*>(attr.value.data()));
    case AttributeValueType::UINT8:
      if (attr.value.size() != 1)
        throw std::runtime_error("Invalid UINT8 size");
      return attr.value[0];
    case AttributeValueType::SOCKADDR: {
      if (attr.value.size() < 4)
        throw std::runtime_error("Invalid SOCKADDR size");
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
        throw std::runtime_error("Unknown address family");
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
      throw std::runtime_error("Unknown attribute value type");
  }
}

class StunMessage {
 private:
  StunHeader _header;
  std::vector<uint8_t> _data;

 public:
  StunMessage(StunHeader header, std::vector<uint8_t> data)
      : _header(std::move(header)), _data(std::move(data)) {}

  StunMessage(
      MessageType messageType,
      std::initializer_list<std::pair<AttributeType, std::vector<uint8_t>>>
          attributes)
      : _header{messageType, 0, 0x2112A442, {0}} {
    for (const auto& attr : attributes) {
      addAttribute(attr.first, attr.second);
    }
  }

  StunMessage(const StunMessage&) = default;
  StunMessage(StunMessage&&) = default;
  StunMessage& operator=(const StunMessage&) = default;
  StunMessage& operator=(StunMessage&&) = default;
  ~StunMessage() = default;

  StunMessage& operator<<(const StunAttribute& attr) {
    addAttribute(attr.type, attr.value);
    return *this;
  }
 StunMessage& addAttribute(const StunAttribute& attr) {
    addAttribute(attr.type, attr.value);
    return *this;
  }

  const uint8_t* headerData() const {
    return reinterpret_cast<const uint8_t*>(&_header);
  }
  size_t headerSize() const { return sizeof(StunHeader); }
  const uint8_t* atrrbutesData() const { return _data.data(); }
  size_t atrrsSize() const { return _data.size(); }
  std::vector<uint8_t> serialize() const {
    std::vector<uint8_t> buf(headerSize() + atrrsSize());
    std::copy(headerData(), headerData() + headerSize(), buf.begin());
    std::copy(atrrbutesData(), atrrbutesData() + atrrsSize(), buf.begin() + headerSize());
    return buf;
  }
  MessageType getMessageType() const { return _header.messageType; }
  StunHeader getHeader() const { return _header; }
  StunAttribute getAttribute(AttributeType type) const {
    for (const StunAttribute& attr :
         makeAttributes(_data.data(), _data.size())) {
      if (attr.type == type) {
        return attr;
      }
    }
    throw std::runtime_error("Attribute not found");
  }

  std::vector<StunAttribute> getAttributes() const {
    return makeAttributes(_data.data(), _data.size());
  }

  void addAttribute(AttributeType type, std::vector<uint8_t> value) {
    StunAttribute attr(type, std::move(value));
    // check value need padding
    if (attr.length % 4 != 0) {
      attr.padding = 4 - (attr.length % 4);
      //pading 0x00
      attr.value.insert(attr.value.end(), attr.padding, 0);
    }
   
    std::vector<uint8_t> serialized = attr.serialize();
    _data.insert(_data.end(), serialized.begin(), serialized.end());
    _header.messageLength =
        htons(ntohs(_header.messageLength) + serialized.size());
  }
};

static StunMessage makeStunMessage(const uint8_t* buffer, size_t length) {
  if (length < sizeof(StunHeader))
    throw std::runtime_error("Buffer too small for STUN message");
  if (!isStunMessage(buffer, length))
    throw std::runtime_error("Isn't  STUN message");
  StunHeader header;
  memcpy(&header, buffer, sizeof(StunHeader));
  uint16_t rawType = (uint16_t)header.messageType;
  header.messageType = (MessageType)((rawType >> 8) | (rawType << 8));
  std::vector<uint8_t> data(buffer + sizeof(StunHeader), buffer + length);
  return StunMessage(std::move(header), std::move(data));
}
static StunMessage makeStunMessage(MessageType type,
                                   const uint8_t* transactionID) {
  StunHeader header;
  header.messageType =
      static_cast<MessageType>(htons(static_cast<uint16_t>(type)));
  header.messageLength = 0;
  header.magicCookie = htonl(0x2112A442);
  memcpy(header.transactionID, transactionID, 12);
  return StunMessage(std::move(header), std::vector<uint8_t>());
}

}  // namespace stun

#endif  // STUN_HPP

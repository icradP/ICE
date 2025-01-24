#include "stun/StunMessage.h"
#include "stun/StunUtils.h"
#include <netinet/in.h>

#include <random>
#include <stdexcept>

#include "stun/StunAttribute.h"
using namespace std;
namespace stun {

std::string MessageType2str(MessageType type) {
  auto it = messageTypeMap.find(type);
  if (it != messageTypeMap.end()) {
    return it->second;
  }
  return "UNKNOWN";
}

bool isStunMessage(const uint8_t* data, size_t len) {
  return ((len >= 20) && (data[0] < 3) && (data[4] == magicCookie[0]) &&
          (data[5] == magicCookie[1]) && (data[6] == magicCookie[2]) &&
          (data[7] == magicCookie[3]));
}

StunMessage makeStunMessage(MessageType type, const uint8_t* transactionID) {
  StunHeader header;
  header.messageType =
      static_cast<MessageType>(htons(static_cast<uint16_t>(type)));
  header.messageLength = 0;
  header.magicCookie = htonl(0x2112A442);
  memcpy(header.transactionID, transactionID, 12);
  return StunMessage(std::move(header), std::vector<uint8_t>());
}
StunMessage makeStunMessage(MessageType type,
                            const std::vector<uint8_t> transactionID) {
  return makeStunMessage(type, transactionID.data());
}

StunMessage makeStunMessage(const uint8_t* buffer, size_t length) {
  if (length < sizeof(StunHeader))
    throw std::runtime_error("Buffer too small for STUN message");
  if (!isStunMessage(buffer, length))
    throw std::runtime_error("Isn't  STUN message");
  StunHeader header;
  memcpy(&header, buffer, sizeof(StunHeader));
  uint16_t rawType = (uint16_t)header.messageType;
  header.messageType = (MessageType)((rawType >> 8) | (rawType << 8));
  std::vector<uint8_t> data(
      buffer + sizeof(StunHeader),
      buffer + sizeof(StunHeader) + ntohs(header.messageLength));
  return StunMessage(std::move(header), std::move(data));
}

StunMessage makeStunMessage(const std::vector<uint8_t> bufv) {
  auto length = bufv.size();
  const auto buffer = bufv.data();
  return (makeStunMessage(buffer, length));
}

StunMessage::StunMessage(StunHeader header, std::vector<uint8_t> data)
    : _header(std::move(header)), _data(std::move(data)) {}

StunMessage& StunMessage::operator<<(const StunAttribute& attr) {
  addAttribute(attr.type, attr.value);
  _attributeMap[attr.type] = attr;
  return *this;
}
StunMessage& StunMessage::addAttribute(const StunAttribute& attr) {
  addAttribute(attr.type, attr.value);
  _attributeMap[attr.type] = attr;
  return *this;
}

bool StunMessage::findAttribute(AttributeType type) {
  if (_data.empty()) return false;
  if (_attributeMap.empty()) {
    auto attributes = makeAttributes(_data.data(), _data.size());
    for (auto& attr : attributes) {
      _attributeMap[attr.type] = attr;
    }
  }
  return _attributeMap.find(type) != _attributeMap.end();
}

const uint8_t* StunMessage::headerData() const {
  return reinterpret_cast<const uint8_t*>(&_header);
}
size_t StunMessage::headerSize() const { return sizeof(StunHeader); }
const uint8_t* StunMessage::atrrbutesData() const { return _data.data(); }
size_t StunMessage::atrrsSize() const { return _data.size(); }
std::vector<uint8_t> StunMessage::serialize() const {
  std::vector<uint8_t> buf(headerSize() + atrrsSize());
  std::copy(headerData(), headerData() + headerSize(), buf.begin());
  std::copy(atrrbutesData(), atrrbutesData() + atrrsSize(),
            buf.begin() + headerSize());
  return buf;
}
MessageType StunMessage::getMessageType() const { return _header.messageType; }
StunHeader StunMessage::getHeader() const { return _header; }
StunAttribute StunMessage::getAttribute(AttributeType type) const {
  for (const StunAttribute& attr : makeAttributes(_data.data(), _data.size())) {
    if (attr.type == type) {
      return attr;
    }
  }
  throw StunException("Attribute not found");
}

std::vector<StunAttribute> StunMessage::getAttributes() const {
  return makeAttributes(_data.data(), _data.size());
}

void StunMessage::addAttribute(AttributeType type, std::vector<uint8_t> value) {
  StunAttribute attr(type, std::move(value));
  // check value need padding
  if (attr.length % 4 != 0) {
    attr.padding = 4 - (attr.length % 4);
    // pading 0x00
    attr.value.insert(attr.value.end(), attr.padding, 0);
  }

  std::vector<uint8_t> serialized = attr.serialize();
  _data.insert(_data.end(), serialized.begin(), serialized.end());
  _header.messageLength =
      htons(ntohs(_header.messageLength) + serialized.size());
}

std::vector<uint8_t> generateTransactionId(size_t length) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dis(0, 255);
  std::vector<uint8_t> transactionId(length);
  for (auto& byte : transactionId) {
    byte = static_cast<uint8_t>(dis(gen));
  }
  return transactionId;
}

}  // namespace stun
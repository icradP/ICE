#ifndef STUN_HPP
#define STUN_HPP

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "StunEnum.h"

namespace stun {

class StunAttribute;
struct StunHeader {
  MessageType messageType;
  uint16_t messageLength;
  uint32_t magicCookie;
  uint8_t transactionID[12];
};

class StunMessage {
 private:
  StunHeader _header;
  std::vector<uint8_t> _data;
  std::unordered_map<AttributeType, StunAttribute> _attributeMap;

 public:
  StunMessage(StunHeader header, std::vector<uint8_t> data);

  StunMessage(const StunMessage&) = default;
  StunMessage(StunMessage&&) = default;
  StunMessage& operator=(const StunMessage&) = default;
  StunMessage& operator=(StunMessage&&) = default;
  ~StunMessage() = default;

  StunMessage& operator<<(const StunAttribute& attr);
  StunMessage& addAttribute(const StunAttribute& attr);

  bool findAttribute(AttributeType type);

  const uint8_t* headerData() const;
  size_t headerSize() const;
  const uint8_t* atrrbutesData() const;
  size_t atrrsSize() const;
  std::vector<uint8_t> serialize() const;
  MessageType getMessageType() const;
  StunHeader getHeader() const;
  StunAttribute getAttribute(AttributeType type) const;

  std::vector<StunAttribute> getAttributes() const;
  void addAttribute(AttributeType type, std::vector<uint8_t> value);
};

 std::string MessageType2str(MessageType type);
 bool isStunMessage(const uint8_t* data, size_t len);
 StunMessage makeStunMessage(const uint8_t* buffer, size_t length);
 StunMessage makeStunMessage(MessageType type,
                                   const uint8_t* transactionID);

}  // namespace stun

#endif  // STUN_HPP

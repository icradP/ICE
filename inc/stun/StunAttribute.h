
#include <cstring>
#include <string>
#include <variant>
#include <vector>

#include "StunEnum.h"

namespace stun {

struct StunMessageErrorCode {
  uint16_t reserved;
  uint8_t err_class; /* code / 100 */
  uint8_t err_code;  /* code % 100 */
  std::vector<uint8_t> err_reason;
};

using AttributeValue =
    std::variant<std::string, uint32_t, uint64_t, uint16_t, uint8_t,
                 std::pair<std::string, uint16_t>, std::vector<uint8_t>,
                 StunMessageErrorCode, std::monostate>;

StunMessageErrorCode makeStunMessageErrorCode(StunMessageErrCodeEnum code);
StunMessageErrorCode makeStunMessageErrorCode(const uint8_t* data, size_t len);
StunMessageErrCodeEnum getStunMessageErrCodeEnum(
    const StunMessageErrorCode& error);
std::string StunMessageErrCodeEnum2str(StunMessageErrCodeEnum code);
std::vector<uint8_t> StunMessageErrCodeEnum2value(StunMessageErrCodeEnum code);
std::vector<uint8_t> serializeStunMessageErrorCode(
    const StunMessageErrorCode& error);

struct StunAttribute {
  AttributeType type;
  uint16_t length;
  std::vector<uint8_t> value;
  uint16_t padding = 0;
  StunAttribute() = default;
  StunAttribute(const StunAttribute&) = default;
  ~StunAttribute() = default;
  StunAttribute(AttributeType type, std::vector<uint8_t> value,
                uint16_t padding = 0);
  StunAttribute(AttributeType type, const char* value, uint16_t padding = 0);
  StunAttribute(AttributeType type, const StunMessageErrorCode& value);
  StunAttribute(AttributeType type, const uint8_t* value, size_t size);
  StunAttribute(AttributeType type, uint32_t num, uint16_t padding = 0);
  std::vector<uint8_t> serialize() const;
};
StunAttribute deserialize(const uint8_t* data, size_t length);

struct AttributeValueStrVisitor {
  std::string operator()(const std::string& value) const;
  std::string operator()(uint32_t value) const;
  std::string operator()(uint64_t value) const;
  std::string operator()(uint16_t value) const;
  std::string operator()(uint8_t value) const;
  std::string operator()(const std::pair<std::string, uint16_t>& value) const;
  std::string operator()(const std::vector<uint8_t>& value) const;
  std::string operator()(const StunMessageErrorCode& value) const;
  std::string operator()(const std::monostate&) const;
};

std::string AttributeValue2str(const AttributeValue& attrvalue);
std::string AttributeType2str(AttributeType type);
std::vector<StunAttribute> makeAttributes(const uint8_t* data, size_t length);
// XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS
// xor_addr = addr ^ magic_cookie
// xor_port = port ^ (magic_cookie >> 16)
// RFC 5389 : 15.2 XOR-MAPPED-ADDRESS : avoid middlebox filtering
std::pair<std::string, uint16_t> getXorAddr(const StunAttribute& attr);
std::vector<uint8_t> makeIpPortVector(const std::string& ip, uint16_t port,
                                      bool isXor = false);
AttributeValue parseAttribute2Variant(const StunAttribute& attr);
const std::string_view ProtocolTransportEnum2str(ProtocolTransport num);
std::vector<uint8_t> makeRequestTransport(ProtocolTransport num);
ProtocolTransport parseRequestTransport(std::vector<uint8_t> test);

}  // namespace stun

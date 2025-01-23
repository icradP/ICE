#pragma once
#include <cstdint>
#include <unordered_map>
#include <string>

namespace stun {

constexpr  uint8_t magicCookie[] = {0x21, 0x12, 0xA4, 0x42};

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

enum ProtocolTransport : uint8_t { TCP = 6, UDP = 17 };

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

 const std::unordered_map<int, std::string> stunMessageErrCodeEnumMap = {
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

// REQUESTED-TRANSPORT

//    This attribute is used by the client to request a specific transport
//    protocol for the allocated transport address.  The value of this
//    attribute is 4 bytes with the following format:
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |    Protocol   |                    RFFU                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

//    The Protocol field specifies the desired protocol.  The codepoints
//    used in this field are taken from those allowed in the Protocol field
//    in the IPv4 header and the NextHeader field in the IPv6 header
//    [Protocol-Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1). 
//    This specification only allows the use of codepoint 17 (User Datagram Protocol).

//    The RFFU field MUST be set to zero on transmission and MUST be
//    ignored on reception.  It is reserved for future uses.



 const std::unordered_map<AttributeType, AttributeValueType>
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

 const std::unordered_map<AttributeType, std::string> attributeTypeMap = {
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


 const std::unordered_map<MessageType, std::string> messageTypeMap = {
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



}  // namespace stun
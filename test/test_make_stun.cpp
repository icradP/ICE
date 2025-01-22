#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "stun/StunMessage.hpp"

using namespace std;
using namespace stun;

void on_message(StunMessage& msg) {
  // find attributetype and cout value
  cout << "Message type: " << MessageType2str(msg.getMessageType()) << endl;
  auto attrs = msg.getAttributes();
  for (StunAttribute& attr : attrs) {
    cout << "Attribute type: " << AttributeType2str(attr.type) << endl;
    cout << "Attribute length: " << attr.length << endl;
    cout << "Attribute value: "
         << AttributeValue2str(parseAttribute2Variant(attr)) << endl;
    if (attr.type == AttributeType::XOR_MAPPED_ADDRESS ||
        attr.type == AttributeType::XOR_PEER_ADDRESS ||
        attr.type == AttributeType::XOR_RELAYED_ADDRESS) {
      auto xorAddr = getXorAddr(attr);
      std::cout << "Attribute value(XOR): " << xorAddr.first << ":"
                << xorAddr.second << std::endl;
    }
    cout << "Attribute value (HEX): "
         << dumphex(attr.value.data(), attr.value.size()) << endl;
    cout << endl;
  }
}

int makeStunMsgTest() {
  std::vector<std::vector<uint8_t>> buffers;
  const uint8_t transactionID[] = {0x54, 0x41, 0x6d, 0x69, 0x74, 0x65,
                                   0x67, 0x4f, 0x71, 0x30, 0x52, 0x79};

  auto stunmsg_1 = makeStunMessage(MessageType::BINDING_REQUEST, transactionID);
  buffers.push_back(stunmsg_1.serialize());

  // TODO: transport type  serialize deserialize
  auto stunmsg_2 =
      makeStunMessage(MessageType::ALLOCATE_REQUEST, transactionID);
  std::vector<uint8_t> transport = {0x11, 0x0, 0x0, 0x0};
  stunmsg_2.addAttribute({AttributeType::REQUESTED_TRANSPORT, transport});
  buffers.push_back(stunmsg_2.serialize());

  // TODO: address serialize ddeserialize
  auto stunmsg_3 =
      makeStunMessage(MessageType::BINDING_RESPONSE, transactionID);
  // TODO: make ip
  std::vector<uint8_t> ipv4xor = {0x00, 0x01, 0xF3, 0xA6,
                                  0x96, 0xFC, 0x51, 0x38};
  stunmsg_3.addAttribute({AttributeType::XOR_MAPPED_ADDRESS, ipv4xor});
  std::vector<uint8_t> ipv4 = {0x00, 0x01, 0xD2, 0xB4, 0xB7, 0xEE, 0xF5, 0x7A};
  stunmsg_3.addAttribute({AttributeType::MAPPED_ADDRESS, ipv4});
  std::vector<uint8_t> iporigin = {0x00, 0x01, 0x2E, 0xFE,
                                   0x77, 0x17, 0xD4, 0x60};
  stunmsg_3.addAttribute(AttributeType::RESPONSE_ORIGIN, iporigin);

  std::string s = {"Coturn-4.5.2 'dan Eider'"};
  std::vector<uint8_t> soft = {s.begin(), s.end()};
  StunAttribute software = {AttributeType::SOFTWARE, soft};
  stunmsg_3.addAttribute(software);
  buffers.push_back(stunmsg_3.serialize());

  // TODO: make NONCE
  auto stunmsg_4 =
      makeStunMessage(MessageType::ALLOCATE_ERROR_RESPONSE, transactionID);
  stunmsg_4.addAttribute(
      {AttributeType::ERROR_CODE,
       makeStunMessageErrorCode(StunMessageErrCodeEnum::UNAUTHORIZED)});
  std::string nonces = {"13cd59a5727d14cf"};
  std::vector<uint8_t> noncev = {nonces.begin(), nonces.end()};
  StunAttribute nonce = {AttributeType::NONCE, noncev};
  stunmsg_4.addAttribute(nonce);
  std::string realmstr = {"icrad.ltd"};
  std::vector<uint8_t> realmv = {realmstr.begin(), realmstr.end()};
  StunAttribute realm{AttributeType::REALM, realmv};
  stunmsg_4.addAttribute(realm);
  stunmsg_4.addAttribute(software);
  buffers.push_back(stunmsg_4.serialize());

  auto stunmsg_5 =
      makeStunMessage(MessageType::ALLOCATE_REQUEST, transactionID);
  // TODO make transport
  stunmsg_5.addAttribute({AttributeType::REQUESTED_TRANSPORT, transport});
  std::string user = {"icrad"};
  std::vector<uint8_t> usernamev = {user.begin(), user.end()};
  StunAttribute username{AttributeType::USERNAME, usernamev};
  stunmsg_5 << username << realm << nonce;
  // TODO make intergity
  std::vector<uint8_t> msg_intergity(20, 0);
  StunAttribute intergity{AttributeType::MESSAGE_INTEGRITY, msg_intergity};
  stunmsg_5.addAttribute(intergity);
  buffers.push_back(stunmsg_5.serialize());

  auto stunmsg_6 =
      makeStunMessage(MessageType::ALLOCATE_RESPONSE, transactionID);
  std::vector<uint8_t> ipv4_relayed = {0x00, 0x01, 0xD0, 0x17,
                                       0x56, 0x05, 0x70, 0x22};
  stunmsg_6.addAttribute({AttributeType::XOR_RELAYED_ADDRESS, ipv4_relayed});
  stunmsg_6.addAttribute({AttributeType::XOR_MAPPED_ADDRESS, ipv4xor});
  // TODO make lifetime
  uint32_t lifetimeu = 600;
  lifetimeu = htonl(lifetimeu);
  stunmsg_6.addAttribute({AttributeType::LIFETIME,
                          reinterpret_cast<uint8_t*>(&lifetimeu),
                          sizeof(uint32_t)});
  stunmsg_6.addAttribute(software);
  stunmsg_6.addAttribute(intergity);
  buffers.push_back(stunmsg_6.serialize());

  auto stunmsg_7 = makeStunMessage(MessageType::REFRESH_REQUEST, transactionID);
  lifetimeu = 0;
  stunmsg_7.addAttribute({AttributeType::LIFETIME,
                          reinterpret_cast<uint8_t*>(&lifetimeu),
                          sizeof(uint32_t)});
  stunmsg_7 << username << realm << nonce << intergity;
  buffers.push_back(stunmsg_7.serialize());

  auto stunmsg_8 =
      makeStunMessage(MessageType::REFRESH_RESPONSE, transactionID);
  stunmsg_8.addAttribute({AttributeType::LIFETIME,
                          reinterpret_cast<uint8_t*>(&lifetimeu),
                          sizeof(uint32_t)});
  stunmsg_8 << software << intergity;
  buffers.push_back(stunmsg_8.serialize());

  for (auto& buf : buffers) {
    try {
      auto msg = makeStunMessage(buf.data(), buf.size());
      cout << "MAKE STUN MESSAGE" << endl;
      on_message(msg);
      cout << endl;
    } catch (const std::exception& e) {
      std::cerr << "Error processing buffer: " << e.what() << std::endl;
      auto msg = makeStunMessage(buf.data(), buf.size());
      cout << "error :\n" << dumphex(buf.data(), buf.size()) << endl;
    }
  }

  return 0;
}

int main(int argc, char** argv) {
  return makeStunMsgTest();
}
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "stun/Stun.h"


using namespace std;
using namespace stun;

void dumpMessage(StunMessage& msg) {
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

int testmakeIP() {
  try {
    // ipv4
    std::vector<uint8_t> ipv4port = makeIpPortVector("183.238.245.122", 53940);
    // ipv6
    std::vector<uint8_t> ipv6port = makeIpPortVector("2001:db8::1", 53940);

    // ipv4
    // std::vector<uint8_t> test1 = makeIpPortVector("1231.123", 53940); //erro 
    std::vector<uint8_t> test2 =
        makeIpPortVector("fe80::f90a:ae77:4678:6e4a", 53940);

    // std::vector<uint8_t> test3 =
    //     makeIpPortVector("fe80::f90a:ae77:4678:6e4a%4", 53940); //error 

  } catch (std::runtime_error& ex) {
    std::cerr << "Error: " << ex.what() << std::endl;
  }
  return 0;
}

int makeStunMsgTest() {
  std::vector<std::vector<uint8_t>> buffers;
  const uint8_t transactionID[] = {0x54, 0x41, 0x6d, 0x69, 0x74, 0x65,
                                   0x67, 0x4f, 0x71, 0x30, 0x52, 0x79};

  auto stunmsg_1 = makeStunMessage(MessageType::BINDING_REQUEST, transactionID);
  buffers.push_back(stunmsg_1.serialize());

  // TODO: transport type  maybe dig litte
  auto stunmsg_2 =
      makeStunMessage(MessageType::ALLOCATE_REQUEST, transactionID);
  StunAttribute transport = {AttributeType::REQUESTED_TRANSPORT,
                             makeRequestTransport(ProtocolTransport::TCP)};
  stunmsg_2.addAttribute(transport);
  buffers.push_back(stunmsg_2.serialize());

  auto stunmsg_3 =
      makeStunMessage(MessageType::BINDING_RESPONSE, transactionID);
  std::vector<uint8_t> ipport = makeIpPortVector("183.238.245.122", 53940);
  std::vector<uint8_t> ipv4xor =
      makeIpPortVector("183.238.245.122", 53940, true);
  std::vector<uint8_t> ipv4 = makeIpPortVector("183.238.245.122", 53940);
  std::vector<uint8_t> iporigin = makeIpPortVector("119.23.212.96", 12030);
  StunAttribute software = {AttributeType::SOFTWARE,
                            "Coturn-4.5.2 \'dan Eider\'"};

  stunmsg_3.addAttribute({AttributeType::MAPPED_ADDRESS, ipport})
      .addAttribute({AttributeType::XOR_MAPPED_ADDRESS, ipv4xor})
      .addAttribute({AttributeType::MAPPED_ADDRESS, ipv4})
      .addAttribute({AttributeType::RESPONSE_ORIGIN, iporigin})
      .addAttribute(software);
  buffers.push_back(stunmsg_3.serialize());

  // TODO: make NONCE
  auto stunmsg_4 =
      makeStunMessage(MessageType::ALLOCATE_ERROR_RESPONSE, transactionID);
  StunAttribute errcoder = {
      AttributeType::ERROR_CODE,
      makeStunMessageErrorCode(StunMessageErrCodeEnum::UNAUTHORIZED)};
  StunAttribute nonce = {AttributeType::NONCE, "13cd59a5727d14cf"};
  StunAttribute realm{AttributeType::REALM, "icrad.ltd"};
  stunmsg_4 << errcoder << nonce << realm << software;
  buffers.push_back(stunmsg_4.serialize());

  auto stunmsg_5 =
      makeStunMessage(MessageType::ALLOCATE_REQUEST, transactionID);
  StunAttribute username{AttributeType::USERNAME, "icrad"};
  // TODO make intergity
  std::vector<uint8_t> msg_intergity(20, 0);
  StunAttribute intergity{AttributeType::MESSAGE_INTEGRITY, msg_intergity};
  stunmsg_5 << transport << username << realm << nonce << intergity;
  buffers.push_back(stunmsg_5.serialize());

  auto stunmsg_6 =
      makeStunMessage(MessageType::ALLOCATE_RESPONSE, transactionID);
  std::vector<uint8_t> ipv4_relayed =
      stun::makeIpPortVector("119.23.212.96", 61701);
  stunmsg_6.addAttribute({AttributeType::XOR_RELAYED_ADDRESS, ipv4_relayed})
      .addAttribute({AttributeType::XOR_MAPPED_ADDRESS, ipv4xor})
      .addAttribute({AttributeType::LIFETIME, 600})
      .addAttribute(software)
      .addAttribute(intergity);
  buffers.push_back(stunmsg_6.serialize());

  auto stunmsg_7 = makeStunMessage(MessageType::REFRESH_REQUEST, transactionID);
  stunmsg_7.addAttribute({AttributeType::LIFETIME, (uint32_t)0});
  stunmsg_7 << username << realm << nonce << intergity;
  buffers.push_back(stunmsg_7.serialize());

  auto stunmsg_8 =
      makeStunMessage(MessageType::REFRESH_RESPONSE, transactionID);
  stunmsg_8.addAttribute({AttributeType::LIFETIME, 600});
  stunmsg_8 << software << intergity;
  buffers.push_back(stunmsg_8.serialize());

  for (auto& buf : buffers) {
    try {
      auto msg = makeStunMessage(buf.data(), buf.size());
      cout << "MAKE STUN MESSAGE" << endl;
      dumpMessage(msg);
      cout << endl;
    } catch (const std::exception& e) {
      std::cerr << "Error processing buffer: " << e.what() << std::endl;
      auto msg = makeStunMessage(buf.data(), buf.size());
      cout << "error :\n" << dumphex(buf.data(), buf.size()) << endl;
    }
  }

  return 0;
}

int main(int argc, char** argv) { return testmakeIP(); }
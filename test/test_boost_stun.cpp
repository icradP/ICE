#include <boost/asio.hpp>
#include <iostream>
#include <vector>

#include "stun/Stun.h"

void dumpMessage(stun::StunMessage& msg) {
  using namespace std;
  using namespace stun;
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

void test_stun_getip() {
  using namespace std;
  using namespace stun;
  try {
   std::vector<uint8_t> transactionID = generateTransactionId();
    auto stunmsg_bind_request =
        makeStunMessage(MessageType::BINDING_REQUEST, transactionID);

    boost::asio::io_context io_context;
    // 创建UDP socket
    boost::asio::ip::udp::socket socket(io_context);
    boost::asio::ip::udp::resolver resolver(io_context);
    boost::asio::ip::udp::endpoint receiver_endpoint =
        *resolver.resolve(boost::asio::ip::udp::v4(), "icrad.ltd", "12030")
             .begin();

    socket.open(receiver_endpoint.protocol());

    // 发送STUN请求消息
    socket.send_to(boost::asio::buffer(stunmsg_bind_request.serialize()),
                   receiver_endpoint);

    // 接收响应
    std::vector<uint8_t> readBuffer(1024);
    boost::asio::ip::udp::endpoint sender_endpoint;
    size_t len =
        socket.receive_from(boost::asio::buffer(readBuffer), sender_endpoint);
    auto stun_recive = makeStunMessage(readBuffer);
    dumpMessage(stun_recive);

  } catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
}

int main() {
  test_stun_getip();
  return 0;
}

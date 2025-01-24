#include <boost/asio.hpp>
#include <iostream>
#include <vector>

#include "stun/Stun.h"
using namespace std;
using namespace stun;

void dumpMessage(stun::StunMessage& msg) {
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

//                         +--------+
//                         |  Test  |
//                         |   I    |
//                         +--------+
//                              |
//                              |
//                              V
//                             /\              /\
//                          N /  \ Y          /  \ Y             +--------+
//           UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
//           Blocked         \ ?  /          \Same/              |   II   |
//                            \  /            \? /               +--------+
//                             \/              \/                    |
//                                              | N                  |
//                                              |                    V
//                                              V                    /\
//                                          +--------+  Sym.      N /  \
//                                          |  Test  |  UDP    <---/Resp\
//                                          |   II   |  Firewall   \ ?  /
//                                          +--------+              \  /
//                                              |                    \/
//                                              V                     |Y
//                   /\                         /\                    |
//    Symmetric  N  /  \       +--------+   N  /  \                   V
//       NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
//                 \Same/      |   I    |     \ ?  /               Internet
//                  \? /       +--------+      \  /
//                   \/                         \/
//                   |                           |Y
//                   |                           |
//                   |                           V
//                   |                           Full
//                   |                           Cone
//                   V              /\
//               +--------+        /  \ Y
//               |  Test  |------>/Resp\---->Restricted
//               |   III  |       \ ?  /
//               +--------+        \  /
//                                  \/
//                                   |N
//                                   |       Port
//                                   +------>Restricted

//                  Figure 2: Flow for type discovery process

const char* stunserverA = "stun.l.google.com";
const char* stunserverB = "icrad.ltd";
const char* stunportA = "19302";
const char* stunportB = "12030";

enum class NetType : uint16_t {

  Blocked,
  Opened,
  SymmetricUDPFirewall,
  FullConeNat,
  SymmetricNat,
  PortRestrictedConeNat,
  RestrictedConeNat,
};

// 假设这些是外部定义的函数
bool TESTI(bool& isEaqul) {
  std::vector<uint8_t> transactionID = generateTransactionId();
  auto stunmsg_bind_request =
      makeStunMessage(MessageType::BINDING_REQUEST, transactionID);
  try {
    boost::asio::io_context io_context;
    boost::asio::ip::udp::socket socket(io_context);
    boost::asio::ip::udp::resolver resolver(io_context);
    boost::asio::ip::udp::endpoint receiver_endpoint =
        *resolver.resolve(boost::asio::ip::udp::v4(), stunserverA, stunportA)
             .begin();
    socket.open(receiver_endpoint.protocol());

    // 发送BINDING REQUEST到Server A
    socket.send_to(boost::asio::buffer(stunmsg_bind_request.serialize()),
                   receiver_endpoint);
    std::vector<uint8_t> readBuffer(1024);
    boost::asio::ip::udp::endpoint sender_endpoint;
    bool receivedResponse = false;
    socket.async_receive_from(
        boost::asio::buffer(readBuffer), sender_endpoint,
        [&](const boost::system::error_code& error, std::size_t bytes_recvd) {
          if (!error) {
            try {
              receivedResponse = true;
              auto stun_recive = makeStunMessage(readBuffer);
              if (stun_recive.findAttribute(AttributeType::MAPPED_ADDRESS)) {
                auto attr =
                    stun_recive.getAttribute(AttributeType::MAPPED_ADDRESS);
                 auto  addr = getAddr(attr);
                if(addr.first ==  receiver_endpoint.address().to_string()){
                    isEaqul = true;
                }else{
                    isEaqul = false;
                }
              }
            } catch (StunException& e) {
              std::cerr << "STUN: " << e.what() << "\n";
            }
          }
        });
    if (io_context.run_one()) {  // 运行IO上下文直到至少一个异步操作完成或超时
      return true;
    } else {
      return false;  // 超时未收到响应
    }
  } catch (std::exception& e) {
    std::cerr << "Exception in TEST1: " << e.what() << "\n";
    return true;
  }
}
bool TESTII() {}
bool TESTIII() {}

std::pair<std::string, uint32_t> getlocalEndport()  // 获取本地公网IP和端口
{
  boost::asio::io_context io_context;
  boost::asio::ip::udp::socket socket(io_context);
  // Open the socket and let the OS assign a local port automatically.
  socket.open(boost::asio::ip::udp::v4());

  // Get the local endpoint which includes the IP address and port number.
  boost::asio::ip::udp::endpoint local_endpoint = socket.local_endpoint();

  // Convert IP to string and port to uint32_t.
  std::string ip_address = local_endpoint.address().to_string();
  uint32_t port = static_cast<uint32_t>(local_endpoint.port());

  return {ip_address, port};
}

NetType test_get_nettype() {
    bool isEaqul = false;
  // 发送第一个绑定请求并检查是否超时
  bool result = TESTI(isEaqul);
  if (!result) {  // 超时情况
    return NetType::Blocked;
  }
  if (isEaqul) {
    if (TESTII()) {
      return NetType::Opened;
    } else {
      return NetType::SymmetricUDPFirewall;
    }
  } else {
    if (TESTII()) {
      return NetType::FullConeNat;
    } else {
      result = TESTI(isEaqul);
      if (isEaqul) {
        if (TESTIII()) {
          return NetType::RestrictedConeNat;
        } else {
          return NetType::PortRestrictedConeNat;
        }
      } else {
        return NetType::SymmetricNat;
      }
    }
  }
}

bool test_stun_get_nettype() {
  std::vector<uint8_t> transactionID = generateTransactionId();
  auto stunmsg_bind_request =
      makeStunMessage(MessageType::BINDING_REQUEST, transactionID);
  try {
    boost::asio::io_context io_context;
    boost::asio::ip::udp::socket socket(io_context);
    boost::asio::ip::udp::resolver resolver(io_context);
    boost::asio::ip::udp::endpoint receiver_endpoint =
        *resolver.resolve(boost::asio::ip::udp::v4(), stunserverA, stunportA)
             .begin();
    socket.open(receiver_endpoint.protocol());

    // 发送BINDING REQUEST到Server A
    socket.send_to(boost::asio::buffer(stunmsg_bind_request.serialize()),
                   receiver_endpoint);
    std::vector<uint8_t> readBuffer(1024);
    boost::asio::ip::udp::endpoint sender_endpoint;
    bool receivedResponse = false;
    socket.async_receive_from(
        boost::asio::buffer(readBuffer), sender_endpoint,
        [&](const boost::system::error_code& error, std::size_t bytes_recvd) {
          if (!error) {
            try {
              receivedResponse = true;
              auto stun_recive = makeStunMessage(readBuffer);
              if (stun_recive.findAttribute(AttributeType::MAPPED_ADDRESS)) {
                auto attr =
                    stun_recive.getAttribute(AttributeType::MAPPED_ADDRESS);
                auto Addr = getAddr(attr);
                if (Addr.first.compare(
                        receiver_endpoint.address().to_string()) != 0) {
                  return true;
                } else {
                  return true;
                }
              }
              if (stun_recive.findAttribute(
                      AttributeType::XOR_MAPPED_ADDRESS)) {
                auto attr =
                    stun_recive.getAttribute(AttributeType::XOR_MAPPED_ADDRESS);
                auto xorAddr = getXorAddr(attr);
                if (xorAddr.first.compare(
                        receiver_endpoint.address().to_string()) != 0) {
                  return true;
                } else {
                  return true;
                }
              }
            } catch (StunException& e) {
              std::cerr << "STUN: " << e.what() << "\n";
            }
          }
        });
    if (io_context.run_one()) {  // 运行IO上下文直到至少一个异步操作完成或超时
      return true;
    } else {
      return true;  // 超时未收到响应
    }
  } catch (std::exception& e) {
    std::cerr << "Exception in TEST1: " << e.what() << "\n";
    return true;
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

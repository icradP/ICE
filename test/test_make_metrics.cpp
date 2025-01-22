

#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include "prometheus/client_metric.h"
#include "prometheus/counter.h"
#include "prometheus/detail/future_std.h"
#include "prometheus/family.h"
#include "prometheus/histogram.h"
#include "prometheus/metric_family.h"
#include "prometheus/metric_type.h"
#include "prometheus/registry.h"
#include "prometheus/summary.h"
#include "prometheus/text_serializer.h"

using namespace prometheus;
using namespace detail;

std::vector<prometheus::MetricFamily> CollectMetrics(
    const std::vector<std::weak_ptr<prometheus::Collectable>>& collectables);

std::vector<MetricFamily> CollectMetrics(
    const std::vector<std::weak_ptr<prometheus::Collectable>>& collectables) {
  auto collected_metrics = std::vector<MetricFamily>{};

  for (auto&& wcollectable : collectables) {
    auto collectable = wcollectable.lock();
    if (!collectable) {
      continue;
    }

    auto&& metrics = collectable->Collect();
    collected_metrics.insert(collected_metrics.end(),
                             std::make_move_iterator(metrics.begin()),
                             std::make_move_iterator(metrics.end()));
  }

  return collected_metrics;
}

// Collectabes ->Serialize-> metrics

class MetricsHandler {
 public:
  explicit MetricsHandler(Registry& registry)
      : bytes_transferred_family_(
            BuildCounter()
                .Name("exposer_transferred_bytes_total")
                .Help("Transferred bytes to metrics services")
                .Register(registry)),
        bytes_transferred_(bytes_transferred_family_.Add({})),
        num_scrapes_family_(BuildCounter()
                                .Name("exposer_scrapes_total")
                                .Help("Number of times metrics were scraped")
                                .Register(registry)),
        num_scrapes_(num_scrapes_family_.Add({})),
        request_latencies_family_(
            BuildSummary()
                .Name("exposer_request_latencies")
                .Help("Latencies of serving scrape requests, in microseconds")
                .Register(registry)),
        request_latencies_(request_latencies_family_.Add(
            {}, Summary::Quantiles{{0.5, 0.05}, {0.9, 0.01}, {0.99, 0.001}})) {}

  void RegisterCollectable(const std::weak_ptr<Collectable>& collectable) {
    std::lock_guard<std::mutex> lock{collectables_mutex_};
    CleanupStalePointers(collectables_);
    collectables_.push_back(collectable);
  }
  void RemoveCollectable(const std::weak_ptr<Collectable>& collectable) {
    std::lock_guard<std::mutex> lock{collectables_mutex_};

    auto locked = collectable.lock();
    auto same_pointer = [&locked](const std::weak_ptr<Collectable>& candidate) {
      return locked == candidate.lock();
    };

    collectables_.erase(std::remove_if(std::begin(collectables_),
                                       std::end(collectables_), same_pointer),
                        std::end(collectables_));
  }

  void handleGet() {
    auto start_time_of_request = std::chrono::steady_clock::now();
    std::vector<MetricFamily> metrics;
    {
      std::lock_guard<std::mutex> lock{collectables_mutex_};
      metrics = CollectMetrics(collectables_);
    }
    const TextSerializer serializer;

    auto bodySize = WriteResponse(serializer.Serialize(metrics));

    auto stop_time_of_request = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        stop_time_of_request - start_time_of_request);
    request_latencies_.Observe(duration.count());
    bytes_transferred_.Increment(bodySize);
    num_scrapes_.Increment();
  }

  static std::size_t WriteResponse(const std::string& body) {
    std::cout << "HTTP/1.1 200 OK\r\n"
              << "Content-Type: text/plain; charset=utf-8\r\n"
              << "Content-Length: " << body.size() << "\r\n\r\n"
              << body << std::endl;
    return body.size();
  }

 

 private:
  static void CleanupStalePointers(
      std::vector<std::weak_ptr<Collectable>>& collectables) {
    collectables.erase(
        std::remove_if(std::begin(collectables), std::end(collectables),
                       [](const std::weak_ptr<Collectable>& candidate) {
                         return candidate.expired();
                       }),
        std::end(collectables));
  }

  std::mutex collectables_mutex_;
  std::vector<std::weak_ptr<Collectable>> collectables_;
  Family<Counter>& bytes_transferred_family_;
  Counter& bytes_transferred_;
  Family<Counter>& num_scrapes_family_;
  Counter& num_scrapes_;
  Family<Summary>& request_latencies_family_;
  Summary& request_latencies_;
};

int test_exposer() {
  auto registry = std::make_shared<Registry>();
  auto& packet_counter = BuildCounter()
                             .Name("observed_packets_total")
                             .Help("Number of observed packets")
                             .Register(*registry);

  auto& tcp_rx_counter =
      packet_counter.Add({{"protocol", "tcp"}, {"direction", "rx"}});
  auto& tcp_tx_counter =
      packet_counter.Add({{"protocol", "tcp"}, {"direction", "tx"}});
  auto& udp_rx_counter =
      packet_counter.Add({{"protocol", "udp"}, {"direction", "rx"}});
  auto& udp_tx_counter =
      packet_counter.Add({{"protocol", "udp"}, {"direction", "tx"}});

  auto& http_requests_counter = BuildCounter()
                                    .Name("http_requests_total")
                                    .Help("Number of HTTP requests")
                                    .Register(*registry);

// # HELP media_list_detail getMediaList detail metric
  // # TYPE media_list_detail gauge
  // media_list_detail{Encodeinfo="H264/mpeg4-generic",aliveSecond="16",bytesSpeed="78.22KB/s",channel="1",createStamp="2025-01-20
  // 18:42:06",originTypeStr="rtp_push",originUrl="rtp://__defaultVhost__/1/865123123123121",peer_ip="172.26.2.1",peer_port="6781",readerCount="0",stream="865123123123121",totalReaderCount="0"}
  // 1
  // media_list_detail{Encodeinfo="mpeg4-generic/H265",aliveSecond="12",bytesSpeed="39.06KB/s",channel="1",createStamp="2025-01-20
  // 18:42:10",originTypeStr="rtp_push",originUrl="rtp://__defaultVhost__/1/865235054918335",peer_ip="172.26.2.1",peer_port="6789",readerCount="0",stream="865235054918335",totalReaderCount="0"}
  // 1

  auto& media_list_detail_gauge =
      BuildGauge()
          .Name("media_list_detail")
          .Help("media_list_detail getMediaList detail metric")
          .Register(*registry);
  media_list_detail_gauge.Add({{"Encodeinfo", "H264/mpeg4-generic"},
                               {"aliveSecond", "16"},
                               {"bytesSpeed", "78.22KB/s"},
                               {"channel", "1"},
                               {"createStamp", "2025-01-20 18:42:06"},
                               {"originTypeStr", "rtp_push"}}).Set(1);

  

  MetricsHandler handle(*registry);
  handle.RegisterCollectable(registry);

  // 剥离改功能，我只需要序列化封装即可。
  //  exposer.RegisterCollectable(registry);

  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    const auto random_value = std::rand();

    if (random_value & 1) tcp_rx_counter.Increment();
    if (random_value & 2) tcp_tx_counter.Increment();
    if (random_value & 4) udp_rx_counter.Increment();
    if (random_value & 8) udp_tx_counter.Increment();

    const std::array<std::string, 4> methods = {"GET", "PUT", "POST", "HEAD"};
    auto method = methods.at(random_value % methods.size());
    http_requests_counter.Add({{"method", method}}).Increment();

    handle.handleGet();
    // std::format();

    registry->Remove(media_list_detail_gauge);
  }
  return 0;
}

int test_media_monitor() {
  auto registry = std::make_shared<Registry>();

  auto& media_list = BuildGauge()
               .Name("media_list")
               .Help("getMediaList metric")
               .Register(*registry);
  auto& media_list_gauge = media_list.Add({{"medianum", "medianum"}});

  auto& mediaobj_BufferLikeString = BuildGauge()
                      .Name("mediaobj_BufferLikeString")
                      .Help("getStatistic_BufferLikeString metric")
                      .Register(*registry);
  auto& mediaobj_BufferLikeString_gauge = mediaobj_BufferLikeString.Add({{"BufferLikeString", "BufferLikeString"}});

  auto& mediaobj_BufferList = BuildGauge()
                  .Name("mediaobj_BufferList")
                  .Help("getStatistic_BufferList metric")
                  .Register(*registry);
  auto& mediaobj_BufferList_gauge = mediaobj_BufferList.Add({{"BufferList", "BufferList"}});

  auto& mediaobj_BufferRaw = BuildGauge()
                   .Name("mediaobj_BufferRaw")
                   .Help("getStatistic_BufferRaw metric")
                   .Register(*registry);
  auto& mediaobj_BufferRaw_gauge = mediaobj_BufferRaw.Add({{"BufferRaw", "BufferRaw"}});

  auto& mediaobj_Frame = BuildGauge()
                 .Name("mediaobj_Frame")
                 .Help("getStatistic_Frame metric")
                 .Register(*registry);
  auto& mediaobj_Frame_gauge = mediaobj_Frame.Add({{"Frame", "Frame"}});

  auto& mediaobj_FrameImp = BuildGauge()
                  .Name("mediaobj_FrameImp")
                  .Help("getStatistic_FrameImp metric")
                  .Register(*registry);
  auto& mediaobj_FrameImp_gauge = mediaobj_FrameImp.Add({{"FrameImp", "FrameImp"}});

  auto& mediaobj_MultiMediaSourceMuxer = BuildGauge()
                         .Name("mediaobj_MultiMediaSourceMuxer")
                         .Help("getStatistic_MultiMediaSourceMuxer metric")
                         .Register(*registry);
  auto& mediaobj_MultiMediaSourceMuxer_gauge = mediaobj_MultiMediaSourceMuxer.Add({{"MultiMediaSourceMuxer", "MultiMediaSourceMuxer"}});

  auto& mediaobj_Socket = BuildGauge()
                .Name("mediaobj_Socket")
                .Help("getStatistic_Socket metric")
                .Register(*registry);
  auto& mediaobj_Socket_gauge = mediaobj_Socket.Add({{"Socket", "Socket"}});

  auto& mediaobj_buffer = BuildGauge()
                .Name("mediaobj_buffer")
                .Help("getStatistic_buffer metric")
                .Register(*registry);
  auto& mediaobj_buffer_gauge = mediaobj_buffer.Add({{"Buffer", "Buffer"}});

  auto& mediaobj_mediasource = BuildGauge()
                   .Name("mediaobj_mediasource")
                   .Help("getStatistic_mediasource metric")
                   .Register(*registry);
  auto& mediaobj_mediasource_gauge = mediaobj_mediasource.Add({{"MediaSource", "MediaSource"}});

  auto& mediaobj_rtmpPacket = BuildGauge()
                  .Name("mediaobj_rtmpPacket")
                  .Help("getStatistic_rtmpPacket metric")
                  .Register(*registry);
  auto& mediaobj_rtmpPacket_gauge = mediaobj_rtmpPacket.Add({{"RtmpPacket", "RtmpPacket"}});

  auto& mediaobj_rtpPacket = BuildGauge()
                   .Name("mediaobj_rtpPacket")
                   .Help("getStatistic_rtpPacket metric")
                   .Register(*registry);
  auto& mediaobj_rtpPacket_gauge = mediaobj_rtpPacket.Add({{"RtpPacket", "RtpPacket"}});

  auto& session_list = BuildGauge()
               .Name("session_list")
               .Help("getAllSession metric")
               .Register(*registry);
  auto& session_list_gauge = session_list.Add({{"sessionnum", "sessionnum"}});

  // Simulate metric updates
  media_list_gauge.Set(0);
  mediaobj_BufferLikeString_gauge.Set(2);
  mediaobj_BufferList_gauge.Set(0);
  mediaobj_BufferRaw_gauge.Set(4);
  mediaobj_Frame_gauge.Set(0);
  mediaobj_FrameImp_gauge.Set(0);
  mediaobj_MultiMediaSourceMuxer_gauge.Set(0);
  mediaobj_Socket_gauge.Set(50);
  mediaobj_buffer_gauge.Set(6);
  mediaobj_mediasource_gauge.Set(1);
  mediaobj_rtmpPacket_gauge.Set(0);
  mediaobj_rtpPacket_gauge.Set(0);
  session_list_gauge.Set(1);

  MetricsHandler handle(*registry);
  handle.RegisterCollectable(registry);
  

  handle.handleGet();

  return 0;
}

int test_serialize() {
  MetricFamily metricFamily;
  ClientMetric metric;

  const std::string name = "my_metric";
  MetricType type = MetricType::Histogram;

  Histogram histogram{{1}};
  histogram.Observe(0);
  histogram.Observe(200);
  metric = histogram.Collect();

  metricFamily.name = name;
  metricFamily.help = "my metric help text";
  metricFamily.type = type;

  metricFamily.metric = std::vector<ClientMetric>{metric};
  std::vector<MetricFamily> families{metricFamily};

  TextSerializer textSerializer;
  auto metric_info = textSerializer.Serialize(families);

  std::cout << "========================================" << std::endl;
  std::cout << metric_info << std::endl;
  return 0;
}

int main(int argc, char** argv) {
  // return test_serialize();
  return test_exposer();
  return test_media_monitor();
}
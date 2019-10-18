#pragma once

#include <chrono>
#include <unordered_map>
#include <functional>

#include <prometheus/exposer.h>
#include <prometheus/histogram.h>

#include "protocols/memcachedl.h"
#include "protocols/headers.h"
#include "utils/pcap.h"

namespace exporter {
    static auto logger = spdlog::stdout_color_mt("exporter");

    static std::function<void(double)> on_data_exporter;
    static const size_t INITIAL_ON_FLIGHT_REQUEST = 1000000; // 1 million baby

    void filter_latencies_system_clock(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

        // Drop invalid packets
        if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only requests that Get commands
        if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


        static std::unordered_map<uint32_t, long> requests_durations(INITIAL_ON_FLIGHT_REQUEST);
        switch(request->magic) {
            case memcached::MSG_TYPE::Request:
                requests_durations[request->opaque] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests_durations.find(request->opaque);
                if (it != std::end(requests_durations)) {
                    long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                    on_data_exporter(now - it->second);
                    requests_durations.erase(request->opaque);
                }
                break;
        }
    }

    void filter_latencies_packet_clock(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

        // Drop invalid packets
        if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // Only requests that Get commands
        if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


        static std::unordered_map<uint32_t, struct timeval> requests_durations(INITIAL_ON_FLIGHT_REQUEST);
        switch(request->magic) {
            case memcached::MSG_TYPE::Request:
                requests_durations[request->opaque] = header->ts;
                break;

            case memcached::MSG_TYPE::Response:
                auto it = requests_durations.find(request->opaque);
                if (it != std::end(requests_durations)) {
                    struct timeval now{};
                    timersub(&header->ts, &it->second, &now);

                    on_data_exporter(now.tv_usec);
                    requests_durations.erase(request->opaque);
                }
                break;
        }
    }


    int exporter_memcached_latencies(const std::string& interface_name, int port, const pcap_handler& handler, int listenPort) {

        logger->info("Starting prometheus endpoint on", listenPort);
        prometheus::Exposer exposer{fmt::format("0.0.0.0:{}", listenPort)};
        auto registry = std::make_shared<prometheus::Registry>();
        exposer.RegisterCollectable(registry);
        auto& latencies_family = prometheus::BuildHistogram()
                .Name("memcached_latencies_ms")
                .Help("Seen latencies in milliseconds")
                .Register(*registry);


        auto& latencies = latencies_family.Add({}, prometheus::Histogram::BucketBoundaries{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                                           11, 12, 13, 14, 15, 16, 17, 18, 19,
                                                                                           20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                                                                                           30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                                                                                           40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                                                                                           50, 55, 60, 65, 70, 75, 80, 85, 90, 95,
                                                                                           100, 110, 120, 130, 140, 150, 160, 170, 180, 190,
                                                                                           200});
        on_data_exporter = [&latencies](double value) { latencies.Observe(value); };


        // Filter only packets directed toward a specific port and that has an TCP payload
        std::string pcap_filter = fmt::format("port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
        std::optional<pcap_t*> handleOpt = pcap_utils::start_live_capture(interface_name, port, pcap_filter);
        if(!handleOpt) return EXIT_FAILURE;

        pcap_t* handle = *handleOpt;

        pcap_loop(handle, 0, handler, nullptr);

        /* And close the session */
        pcap_close(handle);

        return EXIT_SUCCESS;
    }

}

#include <iostream>
#include <chrono>
#include <string>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cerrno>
#include <poll.h>

#include <clipp.h>
#include <spdlog/spdlog.h>
#include <map>

#include "pcap_utils.h"
#include "protocols_headers.h"
#include "memcached_protocol.h"
#include "socket.h"

#include "prometheus/exposer.h"
#include "prometheus/registry.h"
#include "prometheus/histogram.h"

static auto logger = spdlog::stdout_color_mt("main");

static std::map<uint64_t, std::vector<uint8_t>> buffers{};
static std::function<void(std::string_view)> on_data;
static std::function<void(double)> on_data2;
static std::function<void(const uint8_t*, ssize_t len)> on_msg;


void filter_requests(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t) || header->caplen != header->len) {
        logger->error("Dropping packets");
        return;
    }

    std::vector<uint8_t>& buffer = buffers[protocols::get_cnx_id(packet)];

    // We can have multiple requests in one packet, so try to be greedy and iterate over all of them
    const auto payload = protocols::get_tcp_payload_as<uint8_t>(packet);
    const uint8_t* packet_last = (uint8_t*) packet + header->caplen;
    for(const uint8_t* it = payload; it < packet_last;) {

        /* VALID MEMCACHED HEADER
         * If this is a valid memcached header, there is only 2 cases
         * either the request is small enough in order to fit in a single packet
         * either the request is too big and we have to buffer data until we got everything
         */
        const auto* request = (memcached::header_t*)(it);
        if(memcached::is_valid_header(request)) {
            // We are interested only by STORE requests
            if(request->magic != memcached::MSG_TYPE::Request &&
               !(request->opcode == memcached::COMMAND::Set
                 || request->opcode == memcached::COMMAND::Add
                 || request->opcode == memcached::COMMAND::AddQ
                 || request->opcode == memcached::COMMAND::Append
                 || request->opcode == memcached::COMMAND::AppendQ
                 || request->opcode == memcached::COMMAND::RAppend
                 || request->opcode == memcached::COMMAND::RAppendQ
                 || request->opcode == memcached::COMMAND::Decrement
                 || request->opcode == memcached::COMMAND::DecrementQ
                 || request->opcode == memcached::COMMAND::RDecr
                 || request->opcode == memcached::COMMAND::RDecrQ
                 || request->opcode == memcached::COMMAND::Delete
                 || request->opcode == memcached::COMMAND::DeleteQ
                 || request->opcode == memcached::COMMAND::RDelete
                 || request->opcode == memcached::COMMAND::RDeleteQ
                 || request->opcode == memcached::COMMAND::Increment
                 || request->opcode == memcached::COMMAND::IncrementQ
                 || request->opcode == memcached::COMMAND::RIncr
                 || request->opcode == memcached::COMMAND::RIncrQ
                 || request->opcode == memcached::COMMAND::Prepend
                 || request->opcode == memcached::COMMAND::PrependQ
                 || request->opcode == memcached::COMMAND::RPrepend
                 || request->opcode == memcached::COMMAND::RPrependQ
                 || request->opcode == memcached::COMMAND::RSet
                 || request->opcode == memcached::COMMAND::RSetQ
                 || request->opcode == memcached::COMMAND::Replace
                 || request->opcode == memcached::COMMAND::ReplaceQ
                 || request->opcode == memcached::COMMAND::Touch
               )) {
                return;
            }

            // Calculate the size of the memcached request and the packet size in order
            // to check if the payload fit in a single packet or if we should buffer things
            // until we get everything
            const uint32_t request_len = ntohl(request->body_length);
            const uint8_t* last = ((uint8_t*) (request + 1)) + request_len;
            if(last <= packet_last) {
                // Happy path, the request is small enough to fit in a single packet
                logger->debug("Request fit in 1 packet");
                on_msg(it, sizeof(memcached::header_t) + request_len);

                it = last;
                continue;
            }

            // The memcached body does not fit in a single packet, buffer things
            logger->debug("Request too big for one packet");
            if(!buffer.empty()) logger->error("Lost a packet");

            buffer.clear();
            buffer.reserve(sizeof(memcached::header_t) + request_len);
            buffer.insert(buffer.end(), it, packet_last);
            return;

        }

        /* INVALID MEMCACHED HEADER
         * If this is an invalid header, that means
         * either the program is starting and we catched the packet in the middle of a request so we don't have the header
         * either we already seen the header and we are already buffering the data
         *
         * P.s: Even if memcached body length match, there is still a chance that we aggregated two wrong packet so play
         * it safe
         */

        // No ongoing buffering, we have lost the header
        if(buffer.empty()) {
            logger->debug("Header lost");
            return;
        }

        const uint32_t request_len = ntohl(((memcached::header_t*) buffer.data())->body_length);
        const uint8_t* last = it + (request_len - (buffer.size() - sizeof(memcached::header_t)));

        // Our memcached request is still bigger than the whole packet
        // Buffer everything
        if(last > packet_last) {
            logger->debug("Request buffering");
            buffer.insert(buffer.end(), it, packet_last);
            return;
        }

        // Packet size and remaining memcached data match
        // Possibility that's the wrong packet and that the payload match only the size (rare case ?)
        if (last == packet_last) {
            logger->debug("Request full");
            buffer.insert(buffer.end(), it, last);
            on_msg(buffer.data(), buffer.size());
            buffer.clear();
            return;
        }

        // Happy case as we can verify that the next packet is a valid memcached header
        // and so that we haven't screwed up too much
        if(last <= packet_last - sizeof(memcached::header_t)) {

            // Check that we have a valid memcached header, if this is not the case we messed up something up :'x
            if(!memcached::is_valid_header((memcached::header_t*)last)) {
                // We messed up, start from scratch
                logger->error("Request invalid");
                buffer.clear();
                return;
            }

            // Got a valid request as we are correctly aligned
            buffer.insert(buffer.end(), it, last);
            on_msg(buffer.data(), buffer.size());
            buffer.clear();

            it = last;
            logger->debug("Request full");
            continue;
        }

        // The size don't match and we don't have enough bytes to check if the following data is a valid memcached header
        // Play safe and start from sratch
        if(last <= packet_last) {
            logger->debug("Request state unknown");
            buffer.clear();
            return;
        }

        assert(false && "should not be reachable");
    }

}

void filter_keys(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // We are interested only by packets that contains memcached protocol header
    if(!memcached::is_valid_header(request)) return;

    if(memcached::has_key(request)) {
        on_data(memcached::get_key(request));
    }
}

void filter_errors(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(request) || request->magic != memcached::MSG_TYPE::Response) return;

    uint16_t status_code = ntohs(request->rsp_status);
    if(status_code > (uint8_t) memcached::RSP_STATUS::Key_not_found) {
        better_enums::optional<memcached::RSP_STATUS> status = memcached::RSP_STATUS::_from_integral_nothrow(status_code);
        if(status) {
            on_data(fmt::format("{} : {}", status->_to_string(), memcached::get_value(request)));
        }
    }
}

void filter_latencies(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only requests that Get commands
    if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


    static std::unordered_map<uint32_t, long> requests_durations(20000000);
    switch(request->magic) {
        case memcached::MSG_TYPE::Request:
            requests_durations[request->opaque] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            break;

        case memcached::MSG_TYPE::Response:
            auto it = requests_durations.find(request->opaque);
            if (it != std::end(requests_durations)) {
                long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                on_data(fmt::format("{}", now - it->second));
                requests_durations.erase(request->opaque);
            }
            break;
    }
}


void filter_latencies_exporter(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only requests that Get commands
    if(!memcached::is_valid_header(request) || request->opcode != memcached::COMMAND::Get) return;


    static std::unordered_map<uint32_t, long> requests_durations(1000000); // 1 million baby
    switch(request->magic) {
        case memcached::MSG_TYPE::Request:
            requests_durations[request->opaque] = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
            break;

        case memcached::MSG_TYPE::Response:
            auto it = requests_durations.find(request->opaque);
            if (it != std::end(requests_durations)) {
                long now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
                on_data2(now - it->second);
                requests_durations.erase(request->opaque);
            }
            break;
    }
}

void filter_commands(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(request)) return;

    better_enums::optional<memcached::COMMANDS> status = memcached::COMMANDS::_from_integral_nothrow(static_cast<uint8_t >(request->opcode));
    if(status) {
        on_data(status->_to_string());
    }
}

void filter_ttls(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(request) || !memcached::has_extra(*request)) return;

    switch(request->opcode) {
        case memcached::COMMAND::Set:
        case memcached::COMMAND::Add:
        case memcached::COMMAND::Replace:
            on_data(fmt::format("{}", ::ntohl(memcached::get_extra<memcached::MSG_TYPE::Request, memcached::COMMAND::Set>(request)->expiration)));
            break;

        default:
            break;
    }

}

int forward_memcached_traffic(const std::string& interface_name, int port, size_t nb_remote_cnx, const std::function<std::optional<int>()>& create_new_connection) {

    int nb_failure = 0;
    const int max_failure = 3;
    std::vector<int> sockets(nb_remote_cnx);
    for(int i = 0; i < sockets.size() && nb_failure <= max_failure;) {
        if(const auto sock = create_new_connection(); sock.has_value()) {
            sockets[i] = sock.value();
            i++;
        } else {
            nb_failure++;
        }
    }

    if(nb_failure >= max_failure) {
        logger->error("Impossible to create the remote connexion");
        return EXIT_FAILURE;
    }

    // Filter only packets directed toward a specific port and that has an TCP payload
    std::string pcap_filter = fmt::format("dst port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
    std::optional<pcap_t*> handleOpt = pcap_utils::start_live_capture(interface_name, port, pcap_filter);
//    pcap_t* handle = pcap_open_offline("dump.pcap", pcap_err.data());

    if(!handleOpt) return EXIT_FAILURE;
    pcap_t* handle = *handleOpt;

    size_t ix = 0;
    on_msg = [&sockets, &ix, &create_new_connection](const uint8_t* data, size_t len) {
        ssize_t send_ret = 0;
        size_t offset = 0;
        int nb_failure = 0;
        pollfd fds[1];

        for(;;) {
            send_ret = send(sockets[ix], data + offset, len - offset, MSG_NOSIGNAL);
            switch(send_ret) {

                case -1:
                    // Sadly it brokes :'(
                    // Close the cnx and create an other one as the current state of the transfert is unkown
                    if(!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                        logger->error("error during send on socket {} {}/{} -- {}", sockets[ix], offset, len, strerror(errno));
                        goto reconnect;
                    }

                    // Socket full cannot send more data on it
                    // Just load balance on an other cnx
                    if(offset == 0) {
                        ix = (ix + 1) % sockets.size();
                        break;
                    }

                    // Pending data to be send, we have to wait ...
                    fds[0].fd = sockets[ix];
                    fds[0].events = POLLOUT;
                    send_ret = poll(fds, 1, 500);

                    if(send_ret == 0) {
                        logger->error("timeout during send on socket {} {}/{}", sockets[ix], offset, len);
                        goto reconnect;
                    }

                    if(send_ret < 0) {
                        logger->error("error during send on socket {} {}/{} -- {}", sockets[ix], offset, len, strerror(errno));
                        goto reconnect;
                    }
                    break;


                default:
                    offset += send_ret;
                    // We sent data partially, we have to send the remainning
                    // on the same socket, so just retry
                    if(offset < len) {
                        break;
                    }

                    // Sent too much data, should not be possible
                    if (offset > len) {
                        logger->error("Sent to much data to the memcache");
                        goto reconnect;
                    }

                    // Everything is sent :)
                    ix = (ix + 1) % sockets.size();
                    return;

                case -2:
                reconnect:
                    close(sockets[ix]);
                    offset = 0;
                    for(; nb_failure <= max_failure; nb_failure++) {
                        if(const auto sock = create_new_connection(); sock.has_value()) {
                            sockets[ix] = sock.value();
                            nb_failure = 0;
                            break;
                        }
                    }
                    if(nb_failure >= max_failure) {
                        logger->error("Cannot reconnect to remote memcached");
                        throw std::runtime_error("Cannot reconnect to memcached instance");
                    }
                    break;
            }

        }
    };

    pcap_loop(handle, 0, filter_requests, nullptr);
    pcap_close(handle);
    return EXIT_SUCCESS;
}

int sniff_memcached_traffic(const std::string& interface_name, int port, const pcap_handler& handler, int packet_limit) {

    // Basically aggregate results or stream them to stdout
    std::map<std::string, size_t> counters{};
    on_data = (packet_limit > 0)
              ? on_data = [&counters](std::string_view data) { counters[std::string(data)]++; }
              : on_data = [](std::string_view data) { std::cout << data << '\n'; };


    // Filter only packets directed toward a specific port and that has an TCP payload
    std::string pcap_filter = fmt::format("port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
    std::optional<pcap_t*> handleOpt = pcap_utils::start_live_capture(interface_name, port, pcap_filter);
//    pcap_t* handle = pcap_open_offline("dump.pcap", pcap_err.data());

    if(!handleOpt) return EXIT_FAILURE;

    pcap_t* handle = *handleOpt;

    pcap_loop(handle, packet_limit, handler, nullptr);
    for(const auto& kv: counters) {
        std::cout << kv.first << " : " << kv.second << '\n';
    }

    /* And close the session */
    pcap_close(handle);

    return EXIT_SUCCESS;
}

int exporter_memcached_traffic(const std::string& interface_name, int port, const pcap_handler& handler, int listenPort) {

    logger->info("Starting prometheus endpoint on", listenPort);
    prometheus::Exposer exposer{fmt::format("0.0.0.0:{}", listenPort)};
    auto registry = std::make_shared<prometheus::Registry>();
    exposer.RegisterCollectable(registry);
    auto& latencies_family = prometheus::BuildHistogram()
            .Name("latencies")
            .Help("Additional description.")
            .Register(*registry);


    auto& latencies = latencies_family.Add({}, prometheus::Histogram::BucketBoundaries{0,1,5,10,20,30,40,50,60,70,80,90,100,150,200,300,500});
    on_data2 = [&latencies](double value) { latencies.Observe(value); };


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

int main(int argc, char *argv[]){
    using namespace clipp;

    enum class mode {sniff, forward, exporter, help};
    mode selected = mode::help;
    bool verbose = false;

    std::string memcached_hostname;
    int memcached_port;
    size_t memcached_nb_cnx = 200;
    size_t len;

    std::string interface_name;
    int port, listenPort;
    std::string filter;
    int nb_msg = 0;
    std::string destination;
    std::map<std::string, pcap_handler> callbacks{ { "key", filter_keys },
                                                   { "error", filter_errors },
                                                   { "command", filter_commands },
                                                   { "ttl", filter_ttls },
                                                   { "latencies", filter_latencies },
                                                  };

    const auto sniffMode = (
            command("sniff").set(selected, mode::sniff),
            required("-i", "--interface").doc("Interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("Port on which memcached instance is listening") & value("port", port),
            required("-f", "--filter").doc("Filter memcached packets based on {key, error, ttl, command}") & value("filter", filter),
            option("-s", "--stats").doc("Display stats every x packets instead of streaming") & value("number_of_packets", nb_msg),
            option("-v", "--verbose").doc("verbose mode").set(verbose)
            );

    const auto forward = (
            command("forward").set(selected, mode::forward),
            required("-i", "--interface").doc("interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("port on which memcached instance is listening") & value("port", port),
            required("-d", "--destination").doc("Remote memcached that will receive the SETs requests") & value("remote_memcached:port", destination),
            option("-n", "--connections").doc("Number of remote connections to open") & value("number_connection", memcached_nb_cnx),
            option("-v", "--verbose").doc("verbose mode").set(verbose)
            );

    const auto exporter = (
            command("exporter").set(selected, mode::exporter),
                    required("-i", "--interface").doc("interface name to sniff packets on") & value("interface_name", interface_name),
                    required("-p", "--port").doc("port on which memcached instance is listening") & value("port", port),
                    required("-l", "--listen").doc("port on which prometheus endpoint is listening on") & value("listen", listenPort),
                    option("-v", "--verbose").doc("verbose mode").set(verbose)
    );

    const auto cli = (sniffMode | forward | exporter | command("help").set(selected, mode::help));

    if(!parse(argc, argv, cli)) {
        std::cout << make_man_page(cli, "memcache_sniffer");
        return EXIT_FAILURE;
    }

    if(verbose) {
            spdlog::set_level(spdlog::level::debug);
    }

    switch(selected) {
        case mode::sniff:
            if(callbacks.count(filter) <= 0) {
                logger->error("Requested filter {} does not exist", filter);
                return EXIT_FAILURE;
            }

            return sniff_memcached_traffic(interface_name, port, callbacks[filter], nb_msg);

        case mode::forward:
            len = destination.find(':');
            if(len >= destination.size() - 1) {
                logger->error("Invalid memcached remote destination {}. Should respect `hostname:port` format", destination);
                return EXIT_FAILURE;
            }
            memcached_hostname = destination.substr(0, len);
            memcached_port = std::stoi(destination.substr(len+1, destination.size() - len + 1));
            return forward_memcached_traffic(interface_name, port, memcached_nb_cnx, [&memcached_hostname, &memcached_port](){
                return cnx::connect_to(memcached_hostname, memcached_port);
            });

        case mode::help:
            std::cout << make_man_page(cli, "memcache_sniffer");
            return EXIT_SUCCESS;

        case mode::exporter:
            return exporter_memcached_traffic(interface_name, port, filter_latencies_exporter, listenPort);
    }

}

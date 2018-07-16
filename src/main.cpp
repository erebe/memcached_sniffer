#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr
#include <resolv.h>

#include <clipp.h>
#include <spdlog/spdlog.h>
#include <map>

#include "pcap_utils.h"
#include "protocols_headers.h"
#include "memcached_protocol.h"
#include "socket.h"

static auto logger = spdlog::stdout_color_mt("main");

static std::map<uint64_t, std::vector<uint8_t>> buffers{};
static std::function<void(std::string_view)> on_data;
static std::function<void(const uint8_t*, ssize_t len)> on_msg;


void filter_requests(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t) || header->caplen != header->len) {
        logger->error("Dropping packets");
        return;
    }

    std::vector<uint8_t>& buffer = buffers[protocols::get_cnx_id(packet)];

    // We can have multiple request in one packet, so try to be greedy and iterate over all of them
    const auto payload = protocols::get_tcp_payload_as<uint8_t>(packet);
    const uint8_t* packet_last = (uint8_t*) packet + header->caplen;
    for(const uint8_t* it = payload; it < packet_last;) {

        const auto* request = (memcached::header_t*)(it);
        if(memcached::is_valid_header(*request)) {
            // We are interested only by STORE requests
            if(!(request->magic == memcached::MSG_TYPE::Request && request->opcode == memcached::COMMAND::Set)) {
                return;
            }

            // Calculate the size of the memcached request and the packet size in order
            // to check if the payload fit in a single packet or if we should buffer things
            // until we get everything
            const uint32_t request_len = ntohl(request->body_length);
            const uint8_t* last = ((uint8_t*) (request + 1)) + request_len;
            if(last <= packet_last) {
                // Happy path, the request is small enough to fit in a single packet
                logger->debug("Request fit in one packet");
                on_msg(it, sizeof(memcached::header_t) + request_len);

                it = last;
                continue;
            }

            // The memcached body does not fit in a single packet, buffer things
            logger->debug("Request too big for one packet");
            buffer.clear();
            buffer.reserve(sizeof(memcached::header_t) + request_len);
            buffer.insert(buffer.end(), it, packet_last);
            return;

        }

        /*
         * Invalid memcached header
         */

        // No ongoing buffering, we are lost
        if(buffer.empty()) {
            logger->debug("We are lost");
            return;
        }

        // We already have some data bufferized for this connection
        // keep buffering until we got all the payload
        const int request_len = ntohl(((memcached::header_t*) buffer.data())->body_length);
        const uint8_t* last = it + (request_len - (buffer.size() - sizeof(memcached::header_t)));

        // Possibility that's the wrong packet and that the payload match only the size (rare case ?)
        if (last == packet_last) {
            logger->debug("Got one :)");
            buffer.insert(buffer.end(), it, last);
            on_msg(buffer.data(), buffer.size());
            buffer.clear();
            return;
        }

        // Happy case as we can verify that the next packet is a valid memcached header
        if(last <= packet_last - sizeof(memcached::header_t)) {
            // Check that we have a valid memcached header, if this is not the case we messed something up :'x
            if(memcached::is_valid_header(*(memcached::header_t*)last)) {
                buffer.insert(buffer.end(), it, last);
                on_msg(buffer.data(), buffer.size());
                buffer.clear();

                it = last;
                logger->debug("Got one :)");
                continue;
            }

            // Not a valid header after of payload, Start from scratch
            logger->debug("Found Invalid packet");
            buffer.clear();
            return;
        }

        if(last <= packet_last) {
            logger->debug("Can't be sure");
            buffer.clear();
            return;
        }

        // Our memcached request is still bigger than this packet
        logger->debug("Swallowed a whole packet");
        buffer.insert(buffer.end(), it, packet_last);
        return;

    }

}

void filter_keys(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // We are interested only by packets that contains memcached protocol header
    if(!memcached::is_valid_header(*request)) return;

    if(memcached::has_key(request)) {
        on_data(memcached::get_key(request));
    }
}

void filter_errors(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(*request) || request->magic != memcached::MSG_TYPE::Response) return;

    uint16_t status_code = ntohs(request->rsp_status);
    if(status_code > (uint8_t) memcached::RSP_STATUS::Key_not_found) {
        better_enums::optional<memcached::RSP_STATUS> status = memcached::RSP_STATUS::_from_integral_nothrow(status_code);
        if(status) {
            on_data(fmt::format("{} : {}", status->_to_string(), memcached::get_value(request)));
        }
    }
}

void filter_commands(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t)) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(*request)) return;

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
    if(!memcached::is_valid_header(*request) || !memcached::has_extra(*request)) return;

    switch(request->opcode) {
        case memcached::COMMAND::Set:
        case memcached::COMMAND::Add:
        case memcached::COMMAND::Replace:
            on_data(fmt::format("{}", ntohl(memcached::get_extra<memcached::MSG_TYPE::Request, memcached::COMMAND::Set>(request)->expiration)));
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

    std::array<uint8_t*, BUFSIZ> buf{};
    ssize_t ix = 0;
    nb_failure = 0;
    on_msg = [&sockets, &ix, &buf, &create_new_connection, &nb_failure](const uint8_t* data, ssize_t len) {
        ssize_t send_ret = 0;
        ssize_t offset = 0;

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
                    for(; nb_failure <= max_failure;) {
                        if(const auto sock = create_new_connection(); sock.has_value()) {
                            sockets[ix] = sock.value();
                        } else {
                            nb_failure++;
                        }
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

int main(int argc, char *argv[]){
    using namespace clipp;

    enum class mode {sniff, forward, help};
    mode selected = mode::help;
    bool verbose = false;

    std::string memcached_hostname;
    int memcached_port;
    size_t memcached_nb_cnx = 200;
    size_t len;

    std::string interface_name;
    int port;
    std::string filter;
    int nb_msg = 0;
    std::string destination;
    std::map<std::string, pcap_handler> callbacks{ { "key", filter_keys },
                                                   { "error", filter_errors },
                                                   { "command", filter_commands },
                                                   { "ttl", filter_ttls },
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

    const auto cli = (sniffMode | forward | command("help").set(selected, mode::help));

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
    }

}

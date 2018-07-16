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

#include "protocols_headers.h"
#include "memcached_protocol.h"
#include "socket.h"

static auto logger = spdlog::stdout_color_mt("main");

static std::map<uint64_t, std::vector<uint8_t>> buffers{};
static std::map<std::string, size_t> counters{};
static std::function<void(std::string_view)> on_data;
static std::function<void(const std::vector<uint8_t>&)> on_msg;


void filter_packets(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->caplen < sizeof(memcached::header_t) || header->caplen != header->len) {
        logger->error("Dropping packets");
        return;
    }

    std::vector<uint8_t>& buffer = buffers[protocols::get_cnx_id(packet)];
    if(buffer.empty()) {
        const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

        // We are interested only by packets that contains memcached protocol header
        if(!memcached::is_valid_header(*request) || request->magic != memcached::MSG_TYPE::Request || request->opcode != memcached::COMMAND::Set) return;

        // Calculate the size of the memcached request and the packet size in order
        // to check if the payload fit in a single packet or if we should buffer things
        // until we get everything
        uint32_t len = ntohl(request->body_length);
        uint8_t* last = ((uint8_t*) (request + 1)) + len;
        uint8_t* packet_last = (uint8_t*) packet + header->len;
        if(last <= packet_last) {
            // Happy path, the request is small enough to fit in a single packet
            logger->debug("Request fit in one packet");
            buffer.reserve(sizeof(memcached::header_t) + len);
            buffer.insert(buffer.end(), (uint8_t*) request, last);
            on_msg(buffer);
            buffer.clear();
            return;
        }

        // The memcached body does not fit in a single packet, buffer things
        logger->debug("Request too big for one packet");
        buffer.reserve(sizeof(memcached::header_t) + len);
        buffer.insert(buffer.end(), (uint8_t*) request, packet_last);
        return;

    }

    // We already have some data bufferized for this connection
    // keep buffering until we got all the payload
    const uint8_t* payload = protocols::get_tcp_payload_as<uint8_t>(packet);
    const uint8_t* payload_end = (uint8_t*) packet + header->len;
    buffer.insert(buffer.end(), payload, payload_end);

    const int request_len = sizeof(memcached::header_t) + ntohl(((memcached::header_t*) buffer.data())->body_length);
    if(buffer.size() < request_len) {
        //logger->info("Buffering request");
    } else if(buffer.size() == request_len) {
        logger->debug("Request full");
        on_msg(buffer);
        buffer.clear();
    } else if (request_len + sizeof(memcached::header_t) <= buffer.size()
               && memcached::is_valid_header(*((memcached::header_t*) &buffer[request_len]))){
        buffer.resize(request_len);
        on_msg(buffer);
        buffer.clear();
    } else {
        logger->debug("Invalid request size");
        buffer.clear();
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
    if(status_code > 0x01) {
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

    on_data(memcached::COMMANDS::_from_integral(static_cast<uint8_t>(request->opcode))._to_string());
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

int main(int argc, char *argv[])
{
    using namespace clipp;

    enum class mode {sniff, forward, help};
    mode selected = mode::help;

    std::string interface_name;
    int port;
    std::string action;
    size_t nb_msg = 0;
    std::string destination;
    std::map<std::string, pcap_handler> callbacks{ { "keys", filter_keys },
                                                   { "errors", filter_errors },
                                                   { "commands", filter_commands },
                                                   { "ttls", filter_ttls },
                                                   { "packets", filter_packets }
                                                  };

    const auto sniffMode = (
            command("sniff").set(selected, mode::sniff),
            required("-i", "--interface").doc("Interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("Port on which memcached instance is listening") & value("port", port),
            required("-f", "--filter").doc("Filter memcached packets based on {keys, errors, ttls, commands}") & value("filter", action),
            option("-s", "--stats").doc("Display stats every x packets instead of streaming") & value("number_of_packets", nb_msg)
            );

    const auto forward = (
            command("forward").set(selected, mode::forward),
            required("-i", "--interface").doc("interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("port on which memcached instance is listening") & value("port", port),
            required("-d", "--destination").doc("Remote memcached that will receive the SETs requests") & value("remote_memcached", destination)
            );

    const auto cli = (sniffMode | forward | command("help").set(selected, mode::help));

    if(parse(argc, argv, cli)) {
        switch(selected) {
            case mode::sniff: /* ... */ break;
            case mode::forward: /* ... */ break;
            case mode::help: std::cout << make_man_page(cli, "memcache_sniffer"); break;
        }
    } else {
        std::cout << make_man_page(cli, "memcache_sniffer");
        return EXIT_FAILURE;
    }

    if(callbacks.count(action) <= 0) {
        logger->error("Requested filter {} does not exist", action);
        return EXIT_FAILURE;
    }

    std::array<char, PCAP_ERRBUF_SIZE> pcap_err{};
    bpf_u_int32 network_mask = 0;
    bpf_u_int32 network_ip = 0;

    /* Find the properties for the device */
    if (pcap_lookupnet(interface_name.c_str(), &network_ip, &network_mask, pcap_err.data()) == -1) {
        logger->error("Couldn't get netmask for device {} -- {}", interface_name, pcap_err.data());
        return EXIT_FAILURE;
    }

    /* Open the session */
    pcap_t* handle = pcap_open_live(interface_name.c_str(), 0, 0, 1000, pcap_err.data());
    if (handle == NULL) {
        logger->error("Couldn't open device {} -- {}", interface_name.c_str(), pcap_err.data());
        return EXIT_FAILURE;
    }

    /* PCAP filter that will be compiled to an eBPF filter */
    struct bpf_program fp{};
    std::string pcap_filter = fmt::format("port {} and (((ip[2:2] - ((ip[0] & 0x0f) << 2)) - ((tcp[12] & 0xf0 ) >> 2)) > 0)", port);
    if (pcap_compile(handle, &fp, pcap_filter.c_str(), 0, network_ip) == -1) {
        logger->error("Couldn't parse filter {} -- {}", pcap_filter, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        logger->error("Couldn't install filter {} -- {}", pcap_filter, pcap_geterr(handle));
        return EXIT_FAILURE;
    }

//    pcap_t* handle = pcap_open_offline("dump.pcap", pcap_err.data());

    if(nb_msg > 0) {
        on_data = [](std::string_view data) {
            counters[std::string(data)]++;
        };
    } else {
        on_data = [](std::string_view data) {
            std::cout << data << '\n';
        };
    }

    std::array<int, 200> sockets{};
    for(int i = 0; i < sockets.size();) {
        if(const auto sock = cnx::connect_to("192.168.18.18", 11221); sock.has_value()) {
            sockets[i] = sock.value();
            i++;
        }
    }

    std::array<uint8_t*, BUFSIZ> buf;
    int ix = 0;
    on_msg = [&sockets, &ix, &buf](const std::vector<uint8_t>& data) {
        ssize_t send_ret = 0;
        ssize_t offset = 0;

        for(;;) {
            send_ret = send(sockets[ix], data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
            switch(send_ret) {

            case -1:
                // Sadly it brokes :'(
                // Close the cnx and create an other one as the current state of the transfert is unkown
                if(!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                    logger->error("error during send on socket {} {}/{} -- {}", sockets[ix], offset, data.size(), strerror(errno));
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
                if(offset < data.size()) {
                    break;
                }

                // Sent too much data, should not be possible
                if (offset > data.size()) {
                    logger->error("Sent to much data to the memcache");
                    goto reconnect;
                }

                // Everything is sent :)
                ix = (ix + 1) % sockets.size();
                return;

            case -2:
            reconnect:
                close(sockets[ix]);
                sockets[ix] = *cnx::connect_to("192.168.18.18", 11221);
                break;
            }

        }
    };

    pcap_loop(handle, nb_msg, callbacks[action], nullptr);
    for(const auto& kv: counters) {
        std::cout << kv.first << " : " << kv.second << '\n';
    }


    /* And close the session */
    pcap_close(handle);
    return(0);
}

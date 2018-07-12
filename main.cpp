#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/in.h>

#include <clipp.h>
//#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <map>

#include "protocols_headers.h"
#include "memcached_protocol.h"


static auto logger = spdlog::stdout_color_mt("main");


void filter_keys(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->len <= 0) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // We are interested only by packets that contains memcached protocol header
    if(!memcached::is_valid_header(request)) return;

    if(memcached::has_key(request)) {
        std::cout << memcached::get_key(request) << '\n';
    }
}

void filter_errors(u_char* /*args*/, const struct pcap_pkthdr* header, const u_char* packet) {

    // Drop invalid packets
    if(packet == nullptr || header->len <= 0) return;

    const auto request = protocols::get_tcp_payload_as<memcached::header_t>(packet);

    // Only response contains status code of operations
    if(!memcached::is_valid_header(request) || request->magic != memcached::MSG_TYPE::Response) return;

    uint16_t status_code = ntohs(request->rsp_status);
    if(status_code > 0x01) {
        better_enums::optional<memcached::RSP_STATUS> status = memcached::RSP_STATUS::_from_integral_nothrow(status_code);
        if(status) {
            std::cout << status->_to_string() << " : " << memcached::get_value(request) << '\n';
        }
    }
}

int main(int argc, char *argv[])
{
    using namespace clipp;
    std::string interface_name;
    int port;
    std::string action;
    std::map<std::string, pcap_handler> callbacks{ {"keys", filter_keys }, { "errors", filter_errors }};

    const auto cli = (
            required("-i", "--interface").doc("Interface name to sniff packets on") & value("interface_name", interface_name),
            required("-p", "--port").doc("Port on which memcached instance is listening") & value("port", port),
            required("-f", "--filter").doc("Filter memcached packets based on {key, errors, xx}") & value("filter", action)
            ).doc("");


    if (!parse(argc, argv, cli)) {
        std::cerr << make_man_page(cli, argv[0]) << std::endl;
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
    pcap_t* handle = pcap_open_live(interface_name.c_str(), BUFSIZ, 0, 1000, pcap_err.data());
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


    pcap_loop(handle, -1, callbacks[action], NULL);


    /* And close the session */
    pcap_close(handle);
    return(0);
}

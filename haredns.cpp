// protocol: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
// ref:      https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// RFC:      https://www.ietf.org/rfc/rfc1035.txt
#include <thread>
#include <iostream>
#include <vector>
#include <array>
#include <cstdint>

// posix headers
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// project headers
#include "haredns_def.hpp"

struct dns
{
    struct header
    {
        std::uint16_t _id;
        std::uint16_t _control;
        std::uint16_t _question;
        std::uint16_t _answer;
        std::uint16_t _authority;
        std::uint16_t _additional;

        void to_htons()
        {
            _id        = htons(_id);
            _control   = htons(_control);
            _question  = htons(_question);
            _answer    = htons(_answer);
            _authority = htons(_authority);
            _additional= htons(_additional);
        }

        void to_ntohs()
        {
            _id        = ntohs(_id);
            _control   = ntohs(_control);
            _question  = ntohs(_question);
            _answer    = ntohs(_answer);
            _authority = ntohs(_authority);
            _additional= ntohs(_additional);
        }
    };
    header _header{};
    std::vector<std::uint8_t> _body;

    enum class control_code : std::uint16_t {
        QR     = 1,      // 1 bit // Query or Response    // 0 -> request, 1 -> response
        OPCODE = QR + 4, // 4 bits// Message Purpose      // 0 -> QUERY, ...
        AA,              // 1 bit // Authoritative Answer // 0 -> cache, 1 -> authoritative
        TC,              // 1 bit // Truncated            // 0 -> false, 1 -> true
        RD,              // 1 bit // Recursion Desired    // 0 -> iterative, 1 -> recursive
        RA,              // 1 bit // Recursion Available  // 0 -> not recursive, 1 -> recursive (server support)
        Z,               // 1 bit // Zeros
        AD,              // 1 bit // Authenticated data   // DNSSEC
        CD,              // 1 bit // Checking Disabled    // DNSSEC
        RCODE = CD + 4   // 4 bits// Error Codes          // See enum class return_code
    };

    dns() = default;
    dns(std::vector<std::uint8_t> & raw_response)
    {
        std::memcpy(&_header, raw_response.data(), sizeof(header));
        _header.to_ntohs();
        raw_response.erase(raw_response.begin(), std::next(raw_response.begin(), sizeof(header)));
        std::swap(_body, raw_response);
    }


    template<typename ... other_codes>
    void set(int val, control_code const & cc, other_codes && ... codes)
    {
        _header._control |= val << (16 - static_cast<std::uint16_t>(cc));

        if constexpr (sizeof...(other_codes) > 0)
            set(val, std::forward<other_codes...>(codes...));
    }

    void set_query(std::string const & host, query_type qt)
    {
        _body = to_dns_format(host);
        _header._question = 1;
        _header._id = static_cast<std::uint16_t>(std::hash<std::thread::id>{}(std::this_thread::get_id()));

        std::size_t size = _body.size();
        _body.insert(_body.end(), { 0, 0, 0, 0 });

        std::uint8_t * end = _body.data() + size;
        std::uint16_t query_val = htons(static_cast<std::uint16_t>(qt));
        std::memcpy(end, &query_val, sizeof(std::uint16_t));

        end += sizeof(std::uint16_t);
        std::uint16_t in_addr = htons(static_cast<std::uint16_t>(qt));
        std::memcpy(end, &in_addr, sizeof(std::uint16_t));
    }

    auto create_packet() -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> packet(sizeof(header));
        header h = _header;
        h.to_htons();
        std::memcpy(packet.data(), &h, sizeof(header));
        std::copy(_body.begin(), _body.end(), std::back_inserter(packet));
        return packet;
    }

    static
    auto to_dns_format(std::string host) -> std::vector<std::uint8_t>
    {
        if (host.back() != '.')
            host += '.';
        std::vector<std::uint8_t> buf;

        for (auto it = host.begin(); it != host.end();)
        {
            auto dot = std::find(it, host.end(), '.');
            buf.push_back(std::distance(it, dot));
            std::copy(it, dot, std::back_inserter(buf));
            it = std::next(dot);
        }
        buf.push_back('\0');
        return buf;
    }
};

auto operator << (std::ostream& os, dns::header const & h) -> std::ostream&
{
    os << "id: "         << h._id         << "\n"
       << "control: "    << std::bitset<16>(h._control) << "\n"
       << "question: "   << h._question   << "\n"
       << "answer: "     << h._answer     << "\n"
       << "authority: "  << h._authority  << "\n"
       << "additional: " << h._additional << "\n";
    return os;
}

template<typename Iterator>
auto readname(Iterator begin) -> std::pair<std::string, Iterator>
{
    static_assert(sizeof (*begin) == 1);

    std::string hostname;
    for (;;)
    {
        std::uint8_t size = *begin;
        std::copy_n(std::next(begin), size, std::back_inserter(hostname));
        std::advance(begin, size + 1);
        if (size == 0)
            break;
        hostname.push_back('.');
    }
    return {hostname, begin};
}

template<typename IntegerType>
auto ntoh(IntegerType data) -> IntegerType
{
    if constexpr (sizeof(IntegerType) == sizeof(std::uint16_t))
        return ntohs(data);
    else
        return ntohl(data);
}

template<typename IntegerType, typename Iterator>
auto readnet(Iterator & it) -> IntegerType
{
    IntegerType data;
    std::memcpy(&data, std::addressof(*it), sizeof(IntegerType));
    std::advance(it, sizeof(IntegerType));

    if constexpr (std::is_enum_v<IntegerType>)
        return static_cast<IntegerType>(ntoh(static_cast<std::underlying_type_t<IntegerType>>(data)));
    else
        return ntoh(data);
}

template<typename IntegerType, typename Iterator> inline
auto readnet(Iterator && it) -> IntegerType
{
    Iterator i = it;
    return readnet<IntegerType>(i);
}

void show_ip(std::uint32_t ip)
{
    sockaddr_in a;
    a.sin_addr.s_addr = htonl(ip);
    std::cout << inet_ntoa(a.sin_addr) << "\n";
}

struct dns_answer
{
    struct header
    {
        std::uint16_t _answer_addr;
        query_type    _query_type;
        std::uint16_t _class_type;
        std::uint32_t _TTL;
        std::uint16_t _rd_size;
    };

    header _header;
    std::vector<std::uint8_t> _data;

    template<typename Iterator,
             std::enable_if_t<is_iterator_v<Iterator>, int> =0>
    dns_answer(Iterator & it)
    {
        readnet<std::uint16_t>(it); // query type (requested)
        readnet<std::uint16_t>(it); // net type   (requested)

        _header._answer_addr = readnet<std::uint16_t>(it); // read pointer and pointer value
        _header._query_type  = readnet<query_type>(it);    //
        _header._class_type  = readnet<std::uint16_t>(it); // IN
        _header._TTL         = readnet<std::uint32_t>(it); //
        _header._rd_size     = readnet<std::uint16_t>(it); // RD size

        std::cout << "addr: "       << _header._answer_addr<< "\n"
                  << "control: "    << _header._query_type << "\n"
                  << "class_type: " << _header._class_type << "\n"
                  << "TTL: "        << _header._TTL     << "\n"
                  << "rd_size: "    << _header._rd_size  << "\n\n";

        std::copy_n (it, _header._rd_size, std::back_inserter(_data));
        std::advance(it, _header._rd_size);

        switch(_header._query_type)
        {
        case query_type::A:
        {
            std::cout << "IPv4 \n";
            std::uint32_t ip = readnet<std::uint32_t>(_data.begin()); // the IP
            show_ip(ip);
            break;
        }
        case query_type::CNAME:
        {
            std::cout << "CNAME \n";
            break;
        }
        default:
            std::cout << "enum: [" << _header._query_type << "] Not Impl\n";
            break;
        }
    }
};

auto operator << (std::ostream& os, dns_answer::header const & h) -> std::ostream&
{
    os << "addr: "       << h._answer_addr<< "\n"
       << "control: "    << h._query_type << "\n"
       << "class_type: " << h._class_type << "\n"
       << "TTL: "        << h._TTL     << "\n"
       << "rd_size: "    << h._rd_size  << "\n";
    return os;
}

void resolve(std::string host, query_type query, std::string dnsserver)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in addr {
        .sin_family = AF_INET,
        .sin_port   = htons(53),
        .sin_addr.s_addr = inet_addr(dnsserver.c_str())
    };

    dns d;
    d.set(1, dns::control_code::RD);
    d.set_query(host, query);
    std::vector<std::uint8_t> p {d.create_packet()};
    std::cout << d._header << "\n";

    std::cout << "sending \n";
    if (sendto(s, p.data(), p.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        std::cerr << "sendto failed\n";

    std::vector<std::uint8_t> buf(65536);
    socklen_t len = sizeof addr;

    std::cout << "recving \n";
    if (recvfrom(s, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&addr), &len) < 0)
        std::cerr << "recvfrom failed\n";

    // parsing dns packet
    dns response {buf};
    std::cout << response._header;

    int count = 0;
    auto it = response._body.begin();
    for (; it != response._body.end(); ++it)
    {
        std::uint8_t v = *it;
        std::cout << v << "\t" << static_cast<unsigned int>(v) << "\n";
        if (v == 0)
            count++;
        else
            count = 0;
        if (count >= 10)
            break;
    }
    return;

//    auto [hostname, it] = readname(response._body.begin());
//    std::cout << "hostname: " << hostname << "\n";   // hostname
//    std::vector<dns_answer> answers;
////    dns_answer v {it};
//    for (int i = 0; i < response._header._answer; i++)
//    {
//        answers.emplace_back(it);
//    }
}


int main(int argc, char *argv[])
{
    resolve("ip.hare1039.nctu.me", query_type::A, "8.8.8.8");
}

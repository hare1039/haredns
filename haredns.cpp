// protocol: http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html
// ref:      https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
// RFC:      https://www.ietf.org/rfc/rfc1035.txt
// Name Compression: http://www.keyboardbanger.com/dns-message-format-name-compression/

#include <thread>
#include <iostream>
#include <iomanip>
#include <vector>
#include <set>
#include <cstdint>
#include <tuple>
#include <bitset>
#include <cstring>
#include <algorithm>
#include <unordered_map>

// posix headers
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

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

        bool ok() const { return get_error_code() == error_type::noerror; }
        auto get_error_code() const -> error_type { return static_cast<error_type>(0b0000'0000'00001111 & _control); };
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
        std::uint16_t in_addr = htons(static_cast<std::uint16_t>(1 /* IN */));
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

    bool ok() const { return _header.ok(); }

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

    auto readptrname(std::size_t raw_offset) const -> std::string
    {
        auto it = _body.begin();
        std::advance(it, (raw_offset - sizeof(_header)));
        auto [name, _] = readname(it);
        return name;
    }

    template<typename Iterator>
    auto readname(Iterator it) const -> std::pair<std::string, Iterator>
    {
        static_assert(sizeof (*it) == 1); // expect std::uint8_t

        // has compression label
        if (*it & 0b11000000)
        {
            std::uint16_t name_ptr = readnet<std::uint16_t>(it);
            std::uint16_t offset   = name_ptr & 0b0011'1111'11111111;
            return {readptrname(offset), it};
        }
        else if (*it == 0)
        {
            return {"", std::next(it)};
        }
        else
        {
            using namespace std::literals;
            std::string hostname, follow;
            std::uint8_t size = *it;

            std::copy_n(std::next(it), size, std::back_inserter(hostname));
            std::advance(it, size + 1);
            std::tie(follow, it) = readname(it);

            hostname.append("."s + follow);
            return {hostname, it};
        }
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

struct resource_record
{
    std::string   _name;
    query_type    _query_type;
    std::uint16_t _class_type;
    std::uint32_t _TTL;
    std::uint16_t _rd_size;
    std::vector<std::uint8_t> _rd_data;
    std::shared_ptr<dns> _response;

    template<typename Iterator,
             std::enable_if_t<is_iterator_v<Iterator>, int> =0>
    resource_record(Iterator & it, std::shared_ptr<dns> response): _response{response}
    {
        std::tie(_name, it) = response->readname(it);

        _query_type = readnet<query_type>(it);
        _class_type = readnet<std::uint16_t>(it); // should be IN
        _TTL        = readnet<std::uint32_t>(it);
        _rd_size    = readnet<std::uint16_t>(it);

        std::copy_n (it, _rd_size, std::back_inserter(_rd_data));
        std::advance(it, _rd_size);
    }

    auto show_rd_data(std::ostream & os = std::cout) const -> std::ostream&
    {
        switch(_query_type)
        {
        case query_type::A:
        {
            std::uint32_t ip = readnet<std::uint32_t>(_rd_data.begin()); // the IP
            os << ip_to_string(ip);
            break;
        }
        case query_type::NS:
        {
            auto [name, _] = _response->readname(_rd_data.begin());
            os << name;
            break;
        }
        case query_type::CNAME:
        {
            os << "CNAME";
            break;
        }
        case query_type::AAAA:
        {
            if constexpr (is_big_endian())
                for (auto it = _rd_data.begin(); it != _rd_data.end(); std::advance(it, 1))
                    os << std::dec << std::setw(1) << static_cast<int>(*it) << ":";
            else
                for (auto it = _rd_data.rbegin(); it != _rd_data.rend(); std::advance(it, 1))
                    os << std::dec << std::setw(1) << static_cast<int>(*it) << ":";
            break;
        }
        case query_type::SOA:
        {
            auto [m_name, it2] = _response->readname(_rd_data.begin());
            os << m_name << " ";
            auto [r_name, it]  = _response->readname(it2);
            os << r_name << " ";
            for (int i = 0; i < 5; i++)
                os << readnet<std::uint32_t>(it) << " ";
            break;
        }
        case query_type::MX:
        {
            auto it = _rd_data.begin();
            os << readnet<std::uint16_t>(it) << "\t";
            auto [mailname, _]  = _response->readname(it);
            os << mailname;
            break;
        }
        default:
            os << "enum: [" << _query_type << "] Not Impl";
            break;
        }
        return os;
    }

    auto rd_data_as_ip() const -> int_ip
    {
        if (_query_type == query_type::A)
            return readnet<std::uint32_t>(_rd_data.begin());

        std::cerr << "Warning: query A on rd_data_as_ip\n";
        return 0;
    }

    auto rd_data_as_hostname() const -> std::string
    {
        auto [name, _] = _response->readname(_rd_data.begin());
        return name;
    }
};

auto operator << (std::ostream& os, resource_record const & h) -> std::ostream&
{
    os << h._name << "\t" << h._query_type << "\t" << h._TTL << "\t";
    return h.show_rd_data(os);
}

class dns_resolver
{
    std::unordered_map<std::string, std::set<int_ip>> _dns_cache;
public:
    static
    auto resolve(std::string host, query_type query, int_ip dnsserver)
        -> std::tuple<std::vector<resource_record>, std::vector<resource_record>, std::vector<resource_record>, error_type>
    {
        int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        defer _run_1 {[&s]() { close(s); }};
        timeval tv {
            .tv_sec  = 5 /* second */,
            .tv_usec = 0,
        };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

        sockaddr_in addr {
            .sin_family = AF_INET,
            .sin_port   = htons(53),
            .sin_addr.s_addr = htonl(dnsserver)
        };

        {
            dns d;
            d.set_query(host, query);
            d.set(1, dns::control_code::AD);
            std::vector<std::uint8_t> p {d.create_packet()};

            if (sendto(s, p.data(), p.size(), 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
            {
                perror("sendto failed: ");
                return {{}, {}, {}, error_type::plain};
            }
        }

        std::shared_ptr<dns> response {nullptr};
        {
            std::vector<std::uint8_t> buf(65536);
            socklen_t len = sizeof addr;

            if (recvfrom(s, buf.data(), buf.size(), 0, reinterpret_cast<sockaddr*>(&addr), &len) < 0)
            {
                perror("recvfrom failed: ");
                return {{}, {}, {}, error_type::timeout};
            }

            // parsing dns packet
            response = std::make_shared<dns>(buf);
            if (not response->ok())
            {
                std::cout << response->_header;
                return {{}, {}, {}, response->_header.get_error_code()};
            }
        }

        // read questions
        auto it = response->_body.begin();
        for (int i = 0; i < response->_header._question; i++)
        {
            std::tie(std::ignore, it) = response->readname(it); // read name and update 'it'
            readnet<std::uint16_t>(it); // query_type
            readnet<std::uint16_t>(it); // class
        }

        // read answers
        std::vector<resource_record> answers;
        for (int i = 0; i < response->_header._answer; i++)
            answers.emplace_back(it, response);

        // read authorities
        std::vector<resource_record> authorities;
        for (int i = 0; i < response->_header._authority; i++)
            authorities.emplace_back(it, response);

        // read additionals
        std::vector<resource_record> additional;
        for (int i = 0; i < response->_header._additional; i++)
            additional.emplace_back(it, response);

        return std::make_tuple(std::move(answers), std::move(authorities), std::move(additional), error_type::noerror);
    }

    // This function will return -> std::vector<int_ip>, ok
    auto recursive_resolve(std::string host,
                           query_type query,
                           std::set<int_ip> const & dns_servers = root_dns)
        -> std::pair<std::set<int_ip>, error_type>
    {
        if (host.back() != '.')
            host += '.';

        if (auto it = _dns_cache.find(host); it != _dns_cache.end())
            return {it->second, error_type::noerror};

        for (int_ip dns_server : dns_servers)
        {
            std::cout << "Query [" << host << "] @" << ip_to_string(dns_server) << "\n";
            auto&& [ans, auth, addi, error] = resolve(host, query, dns_server);
            if (is_fatal(error))
                return {{}, error};
            else if (error != error_type::noerror)
                continue;

            {
                bool is_final = false;
                for (resource_record & rr : auth)
                {
                    if (rr._query_type == query_type::SOA)
                    {
                        std::cout << "[[auth]] " << rr << "\n";
                        is_final = true;
                    }
                }
                if (is_final)
                    return {{}, error_type::noerror};
            }

            for (resource_record & rr: addi)
            {
                //               std::cout << "[[addi]] " << rr << "\n";
                if (rr._query_type == query_type::A)
                    _dns_cache[rr._name].insert(rr.rd_data_as_ip());
            }

            if (not ans.empty())
            {
                std::set<int_ip> rep;
                for (resource_record & rr: ans)
                {
                    std::cout << "[[ansr]] " << rr << "\n";
                    if (rr._query_type == query_type::A)
                        rep.insert(rr.rd_data_as_ip());
                }
                return {rep, error_type::noerror};
            }
            else
            {
                for (resource_record & rr: auth)
                {
                    auto && [next_dns_server, derror] =
                        recursive_resolve(rr.rd_data_as_hostname(), query_type::A);

                    if (is_fatal(error))
                        return {{}, derror};

                    auto && [ans, error] = recursive_resolve(host, query, next_dns_server);
                    if (is_fatal(error))
                        return {{}, error};
                    else if (error != error_type::noerror)
                        continue;
                    else
                        return {ans, error};
                }
            }
        }
        return {{}, error_type::fatal_timeout};
    }
};

int main(int argc, char *argv[])
{
    dns_resolver resolver;
    auto && [_, err] = resolver.recursive_resolve(argv[1], query_type::A);
    if (err != error_type::noerror)
        std::cout << "Error occurred: dns error code: " << err << "\n";
}

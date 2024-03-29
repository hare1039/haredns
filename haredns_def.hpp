#ifndef HAREDNS_DEF_HPP_
#define HAREDNS_DEF_HPP_

#include <type_traits>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <set>
#include <cstdint>
#include <cstring>

// posix headers
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

using ipv4 = std::uint32_t;
constexpr std::uint16_t MAX_UDP_PAYLOAD_SIZE = 4096;

enum class query_type : std::uint16_t
{
    A     = 1,
    NS    = 2,
    CNAME = 5,
    SOA   = 6,
    PTR   = 12,
    MX    = 15,
    TXT   = 16,
    AAAA  = 28,
    SRV   = 33,
    NAPTR = 35,
    OPT   = 41,
    DS    = 43,
    RRSIG = 46,
    NSEC  = 47,
    DNSKEY= 48,
    NSEC3 = 50,
    IXFR  = 251,
    AXFR  = 252,
    ANY   = 255,
    CAA   = 257
};

auto get_query_type(std::string const & q) -> query_type
{
    if (q == "A")     return query_type::A;
    if (q == "NS")    return query_type::NS;
    if (q == "CNAME") return query_type::CNAME;
    if (q == "SOA")   return query_type::SOA;
    if (q == "MX")    return query_type::MX;
    if (q == "TXT")   return query_type::TXT;
    if (q == "RRSIG") return query_type::RRSIG;
    return query_type::ANY;
}

enum class error_type : std::uint32_t
{
    noerror = 0,
    formerr = 1,
    servfail= 2,
    nxdomain= 3,
    notimp  = 4,
    refused = 5,
    yxdomain= 6,
    xrrset  = 7,
    notauth = 8,
    notzone = 9,
    fatal_timeout = 1 << 20, // non standard fatal error
    plain         = 1 << 30, // non standard recoverable error
    timeout,
};

// https://tools.ietf.org/html/rfc4034#appendix-A.1
enum class dnssec_algorithm : std::uint8_t
{
    DeleteDS   = 0,
    RSAMD5     = 1, // https://tools.ietf.org/html/rfc2537 [NOT RECOMMENDED]
    DH         = 2, // https://tools.ietf.org/html/rfc2539
    DSA        = 3, // https://tools.ietf.org/html/rfc2536 [OPTIONAL]
    ECC        = 4, // TBA
    RSASHA1    = 5, // https://tools.ietf.org/html/rfc3110 [MANDATORY]
    RSASHA1_NSEC3_SHA1 = 7, // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xml
    RSASHA256  = 8,         // https://tools.ietf.org/html/rfc5702
    Indirect   = 252,
    PRIVATEDNS = 253,
    PRIVATEOID = 254,
    RESERVED   = 255
};

bool is_fatal(error_type e)
{
    if (e == error_type::noerror or e >= error_type::plain)
        return false;
    return true;
}

std::set<ipv4> const root_dns =
{{
    3324575748, // "198.41.0.4",     // a.root-servers.net
    3339259593, // "199.9.14.201",   // b.root-servers.net
    3223389196, // "192.33.4.12",    // c.root-servers.net
    3339148045, // "199.7.91.13",    // d.root-servers.net
    3234588170, // "192.203.230.10", // e.root-servers.net
    3221554673, // "192.5.5.241",    // f.root-servers.net
    3228574724, // "192.112.36.4",   // g.root-servers.net
    3328294453, // "198.97.190.53",  // h.root-servers.net
    3223622673, // "192.36.148.17",  // i.root-servers.net
    3225059358, // "192.58.128.30",  // j.root-servers.net
    3238006401, // "193.0.14.129",   // k.root-servers.net
    3339146026, // "199.7.83.42",    // l.root-servers.net
    3389791009, // "202.12.27.33",   // m.root-servers.net
}};

auto ip_to_string(ipv4 ip) -> std::string
{
    sockaddr_in a;
    a.sin_addr.s_addr = htonl(ip);
    return inet_ntoa(a.sin_addr);
}

template<typename IntegerType>
auto ntoh(IntegerType data) -> IntegerType
{
    static_assert(sizeof(IntegerType) == sizeof(std::uint8_t) or
                  sizeof(IntegerType) == sizeof(std::uint16_t) or
                  sizeof(IntegerType) == sizeof(std::uint32_t));

    if constexpr (sizeof(IntegerType) == sizeof(std::uint8_t))
        return data;
    else if constexpr (sizeof(IntegerType) == sizeof(std::uint16_t))
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

// only for enum -> int promotion
template<typename Enum,
         std::enable_if_t<std::is_enum_v<Enum>, int> = 0>
int  operator+(Enum const& e)
{
    return static_cast<std::underlying_type_t<Enum>>(e);
}

template<typename T, typename = void>
struct is_iterator
{
    static constexpr bool value = false;
};

template<typename T>
struct is_iterator<T,
                   typename std::enable_if_t<
                       !std::is_same_v<typename std::iterator_traits<T>::value_type, void>>>
{
    static constexpr bool value = true;
};

template<typename T>
constexpr bool is_iterator_v = is_iterator<T>::value;

template<typename Enum,
         std::enable_if_t<std::is_enum_v<Enum>, int> = 0>
auto operator << (std::ostream& os, Enum e) -> std::ostream&
{
    return os << static_cast<std::underlying_type_t<Enum>>(e);
}

template <typename Callable>
struct defer
{
    Callable _callable;
    defer(defer const &) = delete;
    defer& operator=(defer const &) = delete;

    defer(Callable && c): _callable{std::forward<Callable>(c)} {}
    ~defer() { std::invoke(_callable); }
};

constexpr bool is_big_endian() { return htonl(47) == 47; }

#endif // HAREDNS_DEF_HPP_

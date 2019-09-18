#ifndef HAREDNS_DEF_HPP_
#define HAREDNS_DEF_HPP_

enum class query_type : uint16_t
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
    DS    = 43,
    RRSIG = 46,
    NSEC  = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    OPT   = 41,
    IXFR  = 251,
    AXFR  = 252,
    ANY   = 255,
    CAA   = 257
};

std::array<char const *, 13> const root_dns =
{{
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
    "192.5.5.241",    // f.root-servers.net
    "192.112.36.4",   // g.root-servers.net
    "198.97.190.53",  // h.root-servers.net
    "192.36.148.17",  // i.root-servers.net
    "192.58.128.30",  // j.root-servers.net
    "193.0.14.129",   // k.root-servers.net
    "199.7.83.42",    // l.root-servers.net
    "202.12.27.33",   // m.root-servers.net
}};

void show_ip(std::uint32_t ip)
{
    sockaddr_in a;
    a.sin_addr.s_addr = htonl(ip);
    std::cout << inet_ntoa(a.sin_addr) << "\n";
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
std::ostream& operator << (std::ostream& os, Enum e)
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

#endif // HAREDNS_DEF_HPP_

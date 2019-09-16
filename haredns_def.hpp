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

#endif // HAREDNS_DEF_HPP_

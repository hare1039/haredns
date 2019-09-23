#ifndef HAREDNS_SEC_HPP_
#define HAREDNS_SEC_HPP_

#include <openssl/evp.h>
#include "haredns_def.hpp"

auto shahash(std::vector<std::uint8_t> const & data, EVP_MD const * md) -> std::vector<std::uint8_t>
{
    // OpenSSL 1.0.2s  28 May 2019
    EVP_MD_CTX* context = EVP_MD_CTX_create();
    if (not context)
        std::cerr << "context create error \n";
    defer _run_1 {[context] { EVP_MD_CTX_destroy(context); }};

    if (not EVP_DigestInit_ex(context, md, nullptr))
        std::cerr << "EVP_DigestInit_ex error \n";

    if (not EVP_DigestUpdate(context, data.data(), data.size()))
        std::cerr << "EVP_DigestUpdate error \n";

    std::vector<std::uint8_t> hash(EVP_MAX_MD_SIZE);
    unsigned int hash_length = 0;
    if (not EVP_DigestFinal_ex(context, hash.data(), &hash_length))
        std::cerr << "EVP_DigestFinal_ex error \n";

    hash.erase(std::next(hash.begin(), hash_length), hash.end());

    return hash;
}

#endif // HAREDNS_SEC_HPP_

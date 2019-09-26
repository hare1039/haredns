#ifndef HAREDNS_SEC_HPP_
#define HAREDNS_SEC_HPP_

// OpenSSL/1.1.1c@conan/stable
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

#include "haredns_def.hpp"

bool verify(std::vector<std::uint8_t> &n, std::vector<std::uint8_t> &e,
            std::vector<std::uint8_t> &msg, std::vector<std::uint8_t> &hash)
{
    RSA *rsa = RSA_new();
    defer _run_1 = [rsa] { RSA_free(rsa); };
    RSA_set0_key(rsa,
                 BN_bin2bn(n.data(), n.size(), nullptr),
                 BN_bin2bn(e.data(), e.size(), nullptr),
                 nullptr);

    EVP_PKEY *pk = EVP_PKEY_new();
    defer _run_2 = [pk] { EVP_PKEY_free(pk); };

    EVP_PKEY_assign_RSA(pk, rsa);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, nullptr);
    defer _run_3 = [ctx]{ EVP_PKEY_CTX_free(ctx); };

    EVP_MD_CTX* verify = EVP_MD_CTX_new();
    defer _run_4 = [ctx]{ EVP_MD_CTX_free(verify); };
    EVP_MD_CTX_init(verify);

    EVP_DigestVerifyInit(verify, nullptr, EVP_sha256(), nullptr, pk);
    EVP_DigestVerifyUpdate(verify, msg.data(), msg.size());
    return EVP_DigestVerifyFinal(verify, hash.data(), hash.size());
}


#endif // HAREDNS_SEC_HPP_

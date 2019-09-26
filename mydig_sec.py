import sys
import dns.query
import dns.message
import ipaddress
import time
import enum

root_dns = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4" "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

def has_ip(response, query):
    try:
        if query == "A":
            ipaddress.ip_address(response.answer[0].items[0].to_text())
            return True
        elif query == "NS":
            return response.answer[0].query == 2
        elif query == "MX":
            return response.answer[0].query == 15
    except Exception: pass
    return False

root_ksk = dns.rrset.from_text(".", 1, "IN", "DNSKEY", "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=").items[0].to_text()

def parse(response, query):
    rrs = {}
    if query == "DNSKEY" or query == "A":
        rrs = response.answer
    elif query == "DS" or query == "NS":
        rrs = response.authority

    k = rrsig = name = ""
    for rr in rrs:
        if rr.rdtype == 46: # RRSIG
            rrsig = rr
        else:
            k    = rr
            name = rr.name
    return k, rrsig, name

def dnskey_verify(response):
    dnskey, rrsig_key, name_key = parse(response, "DNSKEY")
    dns.dnssec.validate(dnskey, rrsig_key, {name_key: dnskey})
    print(name_key, "DNSKEY verified")
    return name_key, dnskey

def verify(response, name_key, dnskey, query_type):
    ans, rrsig, name = parse(response, query_type)
    dns.dnssec.validate(ans, rrsig, {name_key: dnskey})
    print(name, "DS verified")

def root_verify(dnskeys):
    for dnskey in dnskeys:
        if dnskey.flags == 257:
            if dnskey.to_text() == root_ksk:
                continue
            else:
                raise Exception("Pubksk not match")
    print("Root verified")

def zone_verify(response, parent):
    verified, _, name = parse(parent, "DS")
    verified = verified.items[0]

    for item in parse(response, "DNSKEY")[0]:
        if item.flags == 257: # 1 on 7 and 15 bit
            pubksk = item
            break

    ds = dns.dnssec.make_ds(name, pubksk, "SHA256" if verified.digest_type == 2 else "SHA1")

    if ds != verified:
        raise Exception("public key verify failed")
    print(name, "verified")

def easy_verify(res, res_type, res_key, upper=None):
    rrkey, dnskey = dnskey_verify(res_key)
    verify(res, rrkey, dnskey, res_type)
    if upper:
        zone_verify(res_key, upper)
    else:
        root_verify(dnskey)


class error_type(enum.Enum):
    no_answer   = 0
    no_error    = 1
    no_dnssec   = 2
    verify_fail = 3
    unknown_error = 4

class resolver:
    def __init__(self):
        self._dns_cache = []

    def resolve(self, hostname, query, where):
        return dns.query.udp(
            dns.message.make_query(hostname, query, want_dnssec=True),
            where,
            timeout=5
        )

    def loop_resolve(self, hostname, query, response, key):
        while True:
            nname = response.authority[0].name.to_text();
            for rr in response.additional:
                nip = rr.items[0].to_text()
                try:
                    res    = self.resolve(hostname, query, nip)
                    reskey = self.resolve(nname, "DNSKEY", nip)

                    if res.answer:
                        err = error_type.no_error
                        return res, reskey, response, err

                    has_ds = False
                    for rr in res.authority:
                        if rr.rdtype == 43: #DS
                            has_ds = True

                    if not has_ds:
                        err = error_type.no_dnssec
                        return res, reskey, response, err

                    easy_verify(res, "DS", reskey, response)
                    response = res
                    key      = reskey
                    break
                except Exception:
                    pass
        return {}, {}, {}, error_type.unknown_error

    def recursive_resolve_root(self, hostname, query):
        for root in root_dns:
            try:
                response   = self.resolve(hostname, query, root)
                nextdnskey = self.resolve(".", "DNSKEY", root)

                easy_verify(response, "DS", nextdnskey)

                if not response.additional:
                    continue

                res, reskey, old_resv, err = self.loop_resolve(hostname, query, response, nextdnskey)
                if err == error_type.no_dnssec:
                    return res, err

                if has_ip(res, query):
                    try:
                        easy_verify(res, "A", reskey, old_resv)
                        return res, err
                    except Exception as e:
                        print(e)
                        return res, error_type.verify_fail
                else:
                    for rr in old_resv.answer:
                        name = rr.items[0].to_text()
                        self._dns_cache.append(name)
                        return recursive_resolve_root(name, query)

            except Exception as e:
                print(e)

if __name__ == "__main__":
    start = time.time()
    resolver = resolver()
    response, err = resolver.recursive_resolve_root(sys.argv[1], sys.argv[2])
    elapsed = time.time() - start
    if err == error_type.no_error:
        for i in response.question:
            print("[[qury]]", i.to_text())

        for i in response.answer:
            print("[[ansr]]", i.to_text())

        msg_size = str(len(response.to_text()))
        print("MSG SIZE rcvd: ", msg_size, "\n")

    elif err == error_type.no_dnssec:
        print("DNSSEC not supported")
    elif err == error_type.verify_fail:
        print("DNSSec Verification failed")
    print("Query time:", elapsed * 1000, "ms")

import dns.resolver


def query_dns_records(domain_name):

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    results = {}

    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            results[record_type] = answers
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return {}
        except dns.resolver.NoNameservers:
            pass
        except Exception:
            pass

    return results

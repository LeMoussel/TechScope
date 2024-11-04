# https://dnspython.readthedocs.io/en/stable/index.html
import dns.resolver

def resolve_dns_record(hostname, rrtype='A'):
    """
    Resolves the specified DNS record type for the given hostname.

    Parameters:
    hostname (str): The hostname to resolve the DNS record for.
    rrtype (str, optional): The resource record type to resolve. Defaults to 'A' (IPv4 address).

    Returns:
    list: A list of the resolved DNS records.
    """
    try:
        answers = dns.resolver.resolve(hostname, rrtype)
        return ([answer.to_text() for answer in answers], '')
    except dns.resolver.NXDOMAIN:
        return ([], f"The hostname '{hostname}' does not exist")
    except dns.resolver.Timeout:
        return ([], f"Timeout occurred while resolving '{rrtype}' record for '{hostname}'")
    except dns.resolver.NoAnswer:
        return ([], f"No '{rrtype}' record found for '{hostname}'")
    except dns.exception.DNSException as e:
        return ([], f"{e}")



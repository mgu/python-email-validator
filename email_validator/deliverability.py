from .exceptions_types import *

import dns.resolver
import dns.exception


def validate_email_deliverability(domain, domain_i18n, timeout=None, dns_resolver=None):
    # Check that the domain resolves to an MX record. If there is no MX record,
    # try an A or AAAA record which is a deprecated fallback for deliverability.
    # Raises an EmailUndeliverableError on failure. On success, returns a dict
    # with deliverability information.

    # If no dns.resolver.Resolver was given, get dnspython's default resolver.
    # Override the default resolver's timeout. This may affect other uses of
    # dnspython in this process.
    if dns_resolver is None:
        from . import DEFAULT_TIMEOUT
        if timeout is None:
            timeout = DEFAULT_TIMEOUT 
        dns_resolver = dns.resolver.get_default_resolver()
        dns_resolver.lifetime = timeout

    deliverability_info = {}

    def dns_resolver_resolve_shim(domain, record):
        try:
            # dns.resolver.Resolver.resolve is new to dnspython 2.x.
            # https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Resolver.resolve
            return dns_resolver.resolve(domain, record)
        except AttributeError:
            # dnspython 2.x is only available in Python 3.6 and later. For earlier versions
            # of Python, we maintain compatibility with dnspython 1.x which has a
            # dnspython.resolver.Resolver.query method instead. The only difference is that
            # query may treat the domain as relative and use the system's search domains,
            # which we prevent by adding a "." to the domain name to make it absolute.
            # dns.resolver.Resolver.query is deprecated in dnspython version 2.x.
            # https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Resolver.query
            return dns_resolver.query(domain + ".", record)

    try:
        # We need a way to check how timeouts are handled in the tests. So we
        # have a secret variable that if set makes this method always test the
        # handling of a timeout.
        if getattr(validate_email_deliverability, 'TEST_CHECK_TIMEOUT', False):
            raise dns.exception.Timeout()

        try:
            # Try resolving for MX records.
            response = dns_resolver_resolve_shim(domain, "MX")

            # For reporting, put them in priority order and remove the trailing dot in the qnames.
            mtas = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in response])

            # Remove "null MX" records from the list (their value is (0, ".") but we've stripped
            # trailing dots, so the 'exchange' is just ""). If there was only a null MX record,
            # email is not deliverable.
            mtas = [(preference, exchange) for preference, exchange in mtas
                    if exchange != ""]
            if len(mtas) == 0:
                raise EmailUndeliverableError("The domain name %s does not accept email." % domain_i18n)

            deliverability_info["mx"] = mtas
            deliverability_info["mx_fallback_type"] = None

        except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):

            # If there was no MX record, fall back to an A record.
            try:
                response = dns_resolver_resolve_shim(domain, "A")
                deliverability_info["mx"] = [(0, str(r)) for r in response]
                deliverability_info["mx_fallback_type"] = "A"
            except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):

                # If there was no A record, fall back to an AAAA record.
                try:
                    response = dns_resolver_resolve_shim(domain, "AAAA")
                    deliverability_info["mx"] = [(0, str(r)) for r in response]
                    deliverability_info["mx_fallback_type"] = "AAAA"
                except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):

                    # If there was no MX, A, or AAAA record, then mail to
                    # this domain is not deliverable.
                    raise EmailUndeliverableError("The domain name %s does not exist." % domain_i18n)

        try:
            # Check for a SPF reject all ("v=spf1 -all") record which indicates
            # no emails are sent from this domain, which like a NULL MX record
            # would indicate that the domain is not used for email.
            response = dns_resolver_resolve_shim(domain, "TXT")
            for rec in response:
                value = b"".join(rec.strings)
                if value.startswith(b"v=spf1 "):
                    deliverability_info["spf"] = value.decode("ascii", errors='replace')
                    if value == b"v=spf1 -all":
                        raise EmailUndeliverableError("The domain name %s does not send email." % domain_i18n)
        except dns.resolver.NoAnswer:
            # No TXT records means there is no SPF policy, so we cannot take any action.
            pass
        except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN):
            # Failure to resolve at this step will be ignored.
            pass

    except dns.exception.Timeout:
        # A timeout could occur for various reasons, so don't treat it as a failure.
        return {
            "unknown-deliverability": "timeout",
        }

    except EmailUndeliverableError:
        # Don't let these get clobbered by the wider except block below.
        raise

    except Exception as e:
        # Unhandled conditions should not propagate.
        raise EmailUndeliverableError(
            "There was an error while checking if the domain name in the email address is deliverable: " + str(e)
        )

    return deliverability_info

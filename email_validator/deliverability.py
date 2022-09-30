import sys

from .exceptions_types import *

import dns.resolver
import dns.asyncresolver
import dns.exception


def validate_email_deliverability(email, timeout=None, dns_resolver=None, _async=False):
    # Check that the domain resolves to an MX record. If there is no MX record,
    # try an A or AAAA record which is a deprecated fallback for deliverability.
    # Raises an EmailUndeliverableError on failure. On success, adds additional
    # validation information to the ValidatedEmail object in the 'email' argument.
    # When _async is False, returns nothing. When _async is True, returns a Future.

    # In tests, 'email' is passed as a string holding a domain name.
    if isinstance(email, str):
        domain_name = email
        email = ValidatedEmail()
        email.ascii_domain = domain_name
        email.domain = domain_name

    # If no dns.resolver.Resolver was given, get dnspython's default resolver.
    # Override the default resolver's timeout. This may affect other uses of
    # dnspython in this process.
    if dns_resolver is None:
        from . import DEFAULT_TIMEOUT
        if timeout is None:
            timeout = DEFAULT_TIMEOUT 
        if not _async:
            dns_resolver = dns.resolver.get_default_resolver()
        else:
            dns_resolver = dns.asyncresolver.get_default_resolver()
        dns_resolver.lifetime = timeout

    if _async:
        import asyncio
        loop = asyncio.get_event_loop()
        fut = loop.create_future()

    def dns_query(domain, record, callback):
        # When run synchronously or with a synchronous dns.resolver instance,
        # the query is executed and the callback function is called immediately
        # with the result or an exception instance.
        if not _async or not isinstance(dns_resolver, dns.asyncresolver.Resolver):
            if isinstance(dns_resolver, dns.asyncresolver.Resolver):
                callback(exception=Exception("Asynchronous dns_resolver cannot be used when called synchronously."))            
            try:
                # We need a way to check how timeouts are handled in the tests. So we
                # have a secret variable that if set makes this method always test the
                # handling of a timeout.
                if getattr(validate_email_deliverability, 'TEST_CHECK_TIMEOUT', False):
                    raise dns.exception.Timeout()

                if sys.version_info < (3,):
                    # dnspython 2.x is only available in Python 3.6 and later. For earlier versions
                    # of Python, we maintain compatibility with dnspython 1.x which has a
                    # dnspython.resolver.Resolver.query method instead. The only difference is that
                    # query may treat the domain as relative and use the system's search domains,
                    # which we prevent by adding a "." to the domain name to make it absolute.
                    # dns.resolver.Resolver.query is deprecated in dnspython version 2.x.
                    # https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Resolver.query
                    callback(response=dns_resolver.query(domain + ".", record))
                else:
                    # dns.resolver.Resolver.resolve is new to dnspython 2.x.
                    # https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Resolver.resolve
                    callback(response=dns_resolver.resolve(domain, record))
            except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                callback(exception=e)

        # When run asynchronously, a task is executed asynchronsouly that executes the DNS
        # query and passes the result or exception to the callback. The callback must eventually
        # call the done() function which finishes the Future for the call to validate_email_deliverability.
        else:
            async def do_query():
                try:
                    callback(response = await dns_resolver.resolve(domain, record))
                except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                    callback(exception = e)
            import asyncio
            asyncio.create_task(do_query())

    def done(exception=None):
        # Timeouts are a local problem, probably, so we don't reject
        # email addresses in that case.
        if exception is dns.exception.Timeout:
            if not _async:
                return
            else:
                fut.set_result(email)

        if not _async:
            if exception:
                raise exception
        else:
            if exception:
                fut.set_exception(exception)
            else:
                # The future returns the validated email object.
                fut.set_result(email)

    def got_spf_result(response=None, exception=None):
        if response:
            # Check for a SPF reject all ("v=spf1 -all") record which indicates
            # no emails are sent from this domain, which like a NULL MX record
            # would indicate that the domain is not used for email.
            # Ignore exceptions.
            for rec in response:
                value = b"".join(rec.strings)
                if value.startswith(b"v=spf1 "):
                    email.spf = value.decode("ascii", errors='replace')
                    if value == b"v=spf1 -all":
                        done(exception=EmailUndeliverableError("The domain name %s does not send email." % email.domain))
                        return
        done()
    
    def check_spf_record():
        dns_query(email.ascii_domain, "TXT", callback=got_spf_result)

    def got_aaaa_record(response=None, exception=None):
        if exception:
            # If there was no MX, A, or AAAA record, then mail to
            # this domain is not deliverable.
            return done(exception=EmailUndeliverableError("The domain name %s does not exist." % email.domain))

        # We got an AAAA record.
        email.mx = [(0, str(r)) for r in response]
        email.mx_fallback_type = "AAAA"

        # Now check SPF.
        check_spf_record()

    def got_a_record(response=None, exception=None):
        if exception:
            # If there was no MX or A record, fall back to an AAAA record.
            dns_query(email.ascii_domain, "AAAA", callback=got_aaaa_record)
            return

        # We got an A record.
        email.mx = [(0, str(r)) for r in response]
        email.mx_fallback_type = "A"

        # Now check SPF.
        check_spf_record()

    def got_mx_record(response=None, exception=None):
        if exception:
            # If there was no MX record, fall back to an A record.
            dns_query(email.ascii_domain, "A", callback=got_a_record)
            return

        # We got one or more MX records.

        # For reporting, put them in priority order and remove the trailing dot in the qnames.
        mtas = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in response])

        # Remove "null MX" records from the list (their value is (0, ".") but we've stripped
        # trailing dots, so the 'exchange' is just ""). If there was only a null MX record,
        # email is not deliverable.
        mtas = [(preference, exchange) for preference, exchange in mtas
                if exchange != ""]
        if len(mtas) == 0:
            done(exception=EmailUndeliverableError("The domain name %s does not accept email." % email.domain))
            return

        email.mx = mtas
        email.mx_fallback_type = None

        # Now check SPF.
        check_spf_record()

    dns_query(email.ascii_domain, "MX", callback=got_mx_record)

    if not _async:
        # In tests, we check the returned object. But it is not used
        # by the main library.
        return email
    else:
        # Return the Future when calling asynchronously.
        return fut

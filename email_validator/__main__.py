# A command-line tool for testing.
#
# Usage:
#
# python -m email_validator
#
# Provide email addresses to validate either as a command-line argument
# or in STDIN separated by newlines. No output will be given for valid
# email addresses. Validation errors will be printed for invalid email
# addresses.

import json
import sys

from .validate_email import *


def __utf8_input_shim(input_str):
    if sys.version_info < (3,):
        return input_str.decode("utf-8")
    return input_str


def __utf8_output_shim(output_str):
    if sys.version_info < (3,):
        return unicode_class(output_str).encode("utf-8")
    return output_str


def main_sync(email):
    try:
        result = validate_email(email)
        print(json.dumps(result.as_dict(), indent=2, sort_keys=True, ensure_ascii=False))
    except EmailNotValidError as e:
        print(__utf8_output_shim(e))


async def main_async(source_iterator):
    # Validate the email addresses pased line-by-line on STDIN asynchronously.
    dns_resolver = caching_resolver(_async=True)
    for line in source_iterator:
        email = __utf8_input_shim(line.strip())
        try:
            print(await validate_email(email, dns_resolver=dns_resolver, _async=True))
        except EmailNotValidError as e:
            print(__utf8_output_shim("{} {}".format(email, e)))


def main():
    if len(sys.argv) > 1:
        # Validate the single email address passed on the command line and
        # print the validation result details as JSON or the validation
        # error message.
        email = __utf8_input_shim(sys.argv[1])
        main_sync(email)
        return

    else:
        # Run the asynchronous tool.
        import asyncio
        asyncio.run(main_async(sys.stdin))


if __name__ == "__main__":
    main()

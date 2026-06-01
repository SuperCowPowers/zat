"""Common Zeek query examples using ZeekLogReader."""

import argparse
import os
import sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

# Local imports
from zat import zeek_log_reader


def clean_value(value):
    """Return None for unset Zeek values and the original value otherwise."""
    if value in (None, "-", "", "(empty)"):
        return None
    return value


def format_value(value, max_length=70):
    """Format values for compact command-line tables."""
    text = str(value)
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def top_counter(rows, field):
    """Count non-empty values for one Zeek field."""
    counter = Counter()
    for row in rows:
        value = clean_value(row.get(field))
        if value is not None:
            counter[value] += 1
    return counter


def sum_by_field(rows, key_field, value_fields):
    """Sum one or more numeric fields grouped by a key field."""
    totals = defaultdict(int)
    for row in rows:
        key = clean_value(row.get(key_field))
        if key is None:
            continue
        for value_field in value_fields:
            value = row.get(value_field, 0)
            if isinstance(value, (int, float)):
                totals[key] += value
    return Counter(totals)


def normalize_uri(uri):
    """Drop query strings and fragments so paths group together."""
    uri = clean_value(uri)
    if uri is None:
        return None
    parsed = urlsplit(uri)
    return parsed.path or uri


def print_counter(title, counter, limit):
    """Print the top values from a Counter with a consistent layout."""
    print("\n{}".format(title))
    print("-" * len(title))
    if not counter:
        print("No matching values found")
        return

    for value, count in counter.most_common(limit):
        print("{:<72} {:>8}".format(format_value(value), count))


def print_http_queries(rows, limit):
    print_counter("Top HTTP hosts", top_counter(rows, "host"), limit)
    print_counter("HTTP methods", top_counter(rows, "method"), limit)
    print_counter("HTTP status codes", top_counter(rows, "status_code"), limit)
    print_counter("HTTP user agents", top_counter(rows, "user_agent"), limit)

    paths = Counter()
    for row in rows:
        path = normalize_uri(row.get("uri"))
        if path is not None:
            paths[path] += 1
    print_counter("Top HTTP paths", paths, limit)


def print_dns_queries(rows, limit):
    print_counter("Top DNS queries", top_counter(rows, "query"), limit)
    print_counter("DNS query types", top_counter(rows, "qtype_name"), limit)
    print_counter("DNS response codes", top_counter(rows, "rcode_name"), limit)
    print_counter("DNS responders", top_counter(rows, "id.resp_h"), limit)


def print_conn_queries(rows, limit):
    print_counter("Top responder hosts", top_counter(rows, "id.resp_h"), limit)
    print_counter("Top responder ports", top_counter(rows, "id.resp_p"), limit)
    print_counter("Connection services", top_counter(rows, "service"), limit)
    print_counter("Connection states", top_counter(rows, "conn_state"), limit)
    print_counter("Bytes by responder host", sum_by_field(rows, "id.resp_h", ["orig_bytes", "resp_bytes"]), limit)


def print_ssl_queries(rows, limit):
    print_counter("Top TLS server names", top_counter(rows, "server_name"), limit)
    print_counter("TLS versions", top_counter(rows, "version"), limit)
    print_counter("Top certificate issuers", top_counter(rows, "issuer"), limit)
    print_counter("Top certificate subjects", top_counter(rows, "subject"), limit)


def print_generic_queries(rows, fields, limit):
    """Fallback for logs without a specialized query set."""
    for field in fields[:6]:
        values = top_counter(rows, field)
        if values:
            print_counter("Top values for {}".format(field), values, limit)


def infer_log_type(path, fields):
    """Infer a Zeek log type from the file name and fields."""
    name = os.path.basename(path).lower()
    if "http" in name or {"host", "method", "uri"}.issubset(fields):
        return "http"
    if "dns" in name or {"query", "qtype_name", "rcode_name"}.issubset(fields):
        return "dns"
    if "conn" in name or {"id.orig_h", "id.resp_h", "id.resp_p", "conn_state"}.issubset(fields):
        return "conn"
    if "ssl" in name or {"server_name", "issuer", "subject"}.intersection(fields):
        return "ssl"
    return "generic"


def summarize_log(path, limit):
    reader = zeek_log_reader.ZeekLogReader(path)
    rows = list(reader.readrows())
    fields = set(reader.field_names)
    log_type = infer_log_type(path, fields)

    print("\n{} ({})".format(path, log_type))
    print("=" * min(len(path) + len(log_type) + 3, 100))
    print("Rows: {:d}".format(len(rows)))

    if log_type == "http":
        print_http_queries(rows, limit)
    elif log_type == "dns":
        print_dns_queries(rows, limit)
    elif log_type == "conn":
        print_conn_queries(rows, limit)
    elif log_type == "ssl":
        print_ssl_queries(rows, limit)
    else:
        print_generic_queries(rows, reader.field_names, limit)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run common query-by-example summaries over Zeek conn/dns/http/ssl logs."
    )
    parser.add_argument("zeek_logs", nargs="+", help="One or more Zeek log files to query")
    parser.add_argument("--top", type=int, default=10, help="Number of values to show for each query")
    args, commands = parser.parse_known_args()

    if commands:
        print("Unrecognized args: %s" % commands)
        sys.exit(1)

    return args


if __name__ == "__main__":
    query_args = parse_args()

    for zeek_log in query_args.zeek_logs:
        summarize_log(os.path.expanduser(zeek_log), query_args.top)

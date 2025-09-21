import ipaddress
import re
from tabulate import tabulate

def load_prefixes(text):
    return [m.group() for m in re.finditer(r'\d+\.\d+\.\d+\.\d+/\d+', text)]

def aggregate_subnets(subnets):
    return ipaddress.collapse_addresses(subnets)

def subtract_subnets(supernet, aggregated_subnets):
    uncovered = [supernet]
    for subnet in sorted(aggregated_subnets, key=lambda n: (n.prefixlen, n.network_address), reverse=True):
        next_uncovered = []
        for un in uncovered:
            if subnet.subnet_of(un):
                next_uncovered.extend(un.address_exclude(subnet))
            else:
                next_uncovered.append(un)
        uncovered = next_uncovered
    return uncovered

def compare_tables(static_text, bgp_text):
    static_prefixes = load_prefixes(static_text)
    bgp_prefixes = load_prefixes(bgp_text)

    static_nets = [ipaddress.ip_network(p, strict=False) for p in static_prefixes]
    bgp_nets = [ipaddress.ip_network(p, strict=False) for p in bgp_prefixes]

    # Missing coverage analysis
    missing_results = []
    serial = 1
    for static_net in static_nets:
        covering_bgp = [bgp_net for bgp_net in bgp_nets if bgp_net.subnet_of(static_net) or static_net.subnet_of(bgp_net)]
        agg_bgp = list(aggregate_subnets(covering_bgp))
        if any(bgp_net.supernet_of(static_net) or bgp_net == static_net for bgp_net in bgp_nets):
            uncovered = []
        else:
            uncovered = subtract_subnets(static_net, agg_bgp)

        if uncovered:
            for miss in uncovered:
                uncovered_subnet = "" if miss == static_net else str(miss)
                missing_results.append([serial, str(static_net), uncovered_subnet])
                serial += 1

    # Full difference analysis (exclusive routes in each table)
    static_set = set(static_nets)
    bgp_set = set(bgp_nets)

    static_only = sorted(str(p) for p in static_set - bgp_set)
    bgp_only = sorted(str(p) for p in bgp_set - static_set)

    max_len = max(len(static_only), len(bgp_only))
    static_only.extend([""] * (max_len - len(static_only)))
    bgp_only.extend([""] * (max_len - len(bgp_only)))

    diff_results = []
    for i in range(max_len):
        diff_results.append([i+1, static_only[i], bgp_only[i]])

    return missing_results, diff_results

if __name__ == "__main__":
    mode = input("Paste [P] or files [F]? ").strip().upper()
    if mode == 'P':
        print("Paste static/Dynamic (expected) routes (blank line to finish):")
        static_routes = ""
        while True:
            line = input()
            if line == "":
                break
            static_routes += line + "\n"
        print("Paste Static/Dynamic (Current Routing table) routes (blank line to finish):")
        bgp_routes = ""
        while True:
            line = input()
            if line == "":
                break
            bgp_routes += line + "\n"
    elif mode == 'F':
        sfile = input("Static/Dynamic (expected) routes filename: ").strip()
        dfile = input("Static/Dynamic (Current routing table) routes filename: ").strip()
        with open(sfile) as f: static_routes = f.read()
        with open(dfile) as f: bgp_routes = f.read()
    else:
        print("Invalid mode.")
        exit(1)

    missing_results, diff_results = compare_tables(static_routes, bgp_routes)

    if not missing_results:
        print("All expected routes are fully covered by current routing table.")
    else:
        print("Missing Subnets in current routing table relative to expected routes:")
        missing_table_str = tabulate(missing_results, headers=["S. No.", "Missing required routes in current RT", "Missing Partial uncovered Subnet in current RT"], tablefmt="grid")
        print(missing_table_str)

    print("\nFull Differences Between expected and current Routes:")
    diff_table_str = tabulate(diff_results, headers=["S. No.", "In expected Only (partial/full)", "In current Only (partial/full)"], tablefmt="grid")
    print(diff_table_str)

    with open("route_comparison_output.txt", "w") as f:
        if missing_results:
            f.write("Missing Subnets in BGP routes relative to Static routes:\n")
            f.write(missing_table_str)
            f.write("\n\n")
        else:
            f.write("All static routes are fully covered by BGP-learned routes.\n\n")
        f.write("Full Differences Between Static and BGP Routes:\n")
        f.write(diff_table_str)

    print("\nOutput saved to route_comparison_output.txt")

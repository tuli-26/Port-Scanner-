import socket
import ipaddress
import csv
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# CONFIGURATION
TIMEOUT = 0.5
DEFAULT_THREADS = 100

# Common TCP services
COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

# GET IP ADDRESSES
def get_ips(target):

    # Single IP
    try:
        ip = ipaddress.ip_address(target)
        return [str(ip)]

    except ValueError:
        pass

    # Subnet
    try:
        network = ipaddress.ip_network(
            target,
            strict=False
        )

        hosts = list(network.hosts())

        # Handles a /32 network
        if not hosts:
            hosts = [network.network_address]

        return [str(ip) for ip in hosts]

    except ValueError:
        print("\n[ERROR] Invalid IP address or subnet.")
        return []

# SERVICE IDENTIFICATION
def get_service(port):

    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")

    except OSError:
        return "Unknown"

# BANNER GRABBING
def grab_banner(sock, port):

    try:

        if port in (80, 8000, 8008, 8080):

            request = (
                "HEAD / HTTP/1.0\r\n"
                "Host: localhost\r\n"
                "\r\n"
            )

            sock.sendall(request.encode())

            data = sock.recv(1024)

        else:

            sock.settimeout(0.3)
            data = sock.recv(1024)

        if data:

            banner = data.decode(
                "utf-8",
                errors="ignore"
            )

            # Keep only HTTP headers
            if port in (80, 8000, 8008, 8080):

                headers = banner.split("\r\n\r\n")[0]

                return headers[:300]

            banner = banner.replace(
                "\r", " "
            ).replace(
                "\n", " "
            ).strip()

            return banner[:150]

    except (
        socket.timeout,
        socket.error,
        OSError
    ):
        pass

    return ""

# SCAN ONE PORT
def scan_port(ip, port):

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(TIMEOUT)

    start = time.perf_counter()

    try:

        result = sock.connect_ex(
            (ip, port)
        )

        elapsed = (
            time.perf_counter() - start
        ) * 1000

        # OPEN
        if result == 0:

            service = get_service(port)

            banner = grab_banner(
                sock,
                port
            )

            return {
                "ip": ip,
                "port": port,
                "status": "OPEN",
                "service": service,
                "banner": banner,
                "latency": round(
                    elapsed,
                    2
                )
            }

        # CLOSED
        return {
            "ip": ip,
            "port": port,
            "status": "CLOSED",
            "service": "",
            "banner": "",
            "latency": round(
                elapsed,
                2
            )
        }

    except socket.timeout:

        return {
            "ip": ip,
            "port": port,
            "status": "TIMEOUT",
            "service": "",
            "banner": "",
            "latency": ""
        }

    except socket.error:

        return {
            "ip": ip,
            "port": port,
            "status": "ERROR",
            "service": "",
            "banner": "",
            "latency": ""
        }

    finally:

        sock.close()

# SAVE RESULTS TO CSV
def save_csv(results):

    filename = "scan_results.csv"

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP Address",
            "Port",
            "Status",
            "Service",
            "Banner",
            "Latency (ms)"
        ])

        for result in results:

            writer.writerow([
                result["ip"],
                result["port"],
                result["status"],
                result["service"],
                result["banner"],
                result["latency"]
            ])

    return filename


# MAIN PROGRAM
def main():

    print("\n" + "=" * 65)
    print("             PYTHON NETWORK PORT SCANNER")
    print("=" * 65)

    # TARGET INPUT
    target = input(
        "\nEnter IP or subnet\n"
        "Target: "
    ).strip()

    # PORT INPUT
    try:

        start_port = int(
            input("Enter starting port: ")
        )

        end_port = int(
            input("Enter ending port: ")
        )

    except ValueError:

        print("\n[ERROR] Port must be a number.")
        return

    # VALIDATE PORT
    if not (
        1 <= start_port <= 65535
        and
        1 <= end_port <= 65535
    ):

        print(
            "\n[ERROR] Port must be between "
            "1 and 65535."
        )

        return

    if start_port > end_port:

        print(
            "\n[ERROR] Starting port cannot "
            "be greater than ending port."
        )

        return

    # THREAD INPUT
    try:

        thread_input = input(
            f"Enter number of threads "
            f"(default {DEFAULT_THREADS}): "
        ).strip()

        if thread_input:

            threads = int(thread_input)

        else:

            threads = DEFAULT_THREADS

    except ValueError:

        print("\n[ERROR] Invalid thread number.")
        return

    if threads < 1:

        print(
            "\n[ERROR] Thread count must be "
            "greater than 0."
        )

        return

    # GET IP LIST
    ip_list = get_ips(target)

    if not ip_list:
        return

    # CALCULATE SCAN SIZE
    ports_per_host = (
        end_port - start_port + 1
    )

    total_scans = (
        len(ip_list) * ports_per_host
    )

    # DISPLAY SCAN INFORMATION

    print("\n" + "-" * 65)

    print(f"Target              : {target}")
    print(f"Hosts               : {len(ip_list)}")
    print(
        f"Port range          : "
        f"{start_port}-{end_port}"
    )
    print(
        f"Ports per host      : "
        f"{ports_per_host}"
    )
    print(
        f"Total TCP checks    : "
        f"{total_scans}"
    )
    print(f"Threads             : {threads}")

    print("-" * 65)

    # START SCAN
    print("\nStarting scan...\n")

    start_time = time.perf_counter()

    scan_results = []

    # Generate tasks
    tasks = (
        (ip, port)
        for ip in ip_list
        for port in range(
            start_port,
            end_port + 1
        )
    )

    # THREAD POOL
    with ThreadPoolExecutor(
        max_workers=threads
    ) as executor:

        futures = [
            executor.submit(
                scan_port,
                ip,
                port
            )
            for ip, port in tasks
        ]

        completed = 0

        for future in as_completed(futures):

            result = future.result()

            scan_results.append(result)

            completed += 1

            # Display open ports
            if result["status"] == "OPEN":

                print(
                    f"[OPEN] "
                    f"{result['ip']}:"
                    f"{result['port']} "
                    f"({result['service']})"
                )

    # CALCULATE DURATION
    duration = (
        time.perf_counter()
        - start_time
    )

    # SORT RESULTS
    scan_results.sort(
        key=lambda x: (
            ipaddress.ip_address(
                x["ip"]
            ),
            x["port"]
        )
    )

    # STATISTICS
    open_ports = sum(
        1
        for result in scan_results
        if result["status"] == "OPEN"
    )

    closed_ports = sum(
        1
        for result in scan_results
        if result["status"] == "CLOSED"
    )

    timeout_ports = sum(
        1
        for result in scan_results
        if result["status"] == "TIMEOUT"
    )

    error_ports = sum(
        1
        for result in scan_results
        if result["status"] == "ERROR"
    )

    # SAVE CSV
    csv_file = save_csv(
        scan_results
    )

    # FINAL SUMMARY
    print("\n" + "-" * 65)
    print("                    SCAN SUMMARY")
    print("-" * 65)

    print(f"\nTarget              : {target}")
    print(
        f"Scan time           : " 
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    print(
        f"Hosts scanned       : "
        f"{len(ip_list)}"
    )
    print(
        f"Total TCP checks    : "
        f"{total_scans}"
    )
    print(
        f"Open ports          : "
        f"{open_ports}"
    )
    print(
        f"Closed ports        : "
        f"{closed_ports}"
    )
    print(
        f"Timeouts            : "
        f"{timeout_ports}"
    )
    print(
        f"Errors              : "
        f"{error_ports}"
    )
    print(
        f"Scan duration       : "
        f"{duration:.2f} seconds"
    )
    print(
        f"CSV report          : "
        f"{csv_file}"
    )

    # OPEN PORT DETAILS
    print("\n" + "-" * 65)
    print("                  OPEN PORT DETAILS")
    print("-" * 65)

    if open_ports == 0:

        print("\nNo open ports found.")

    else:

        for result in scan_results:

            if result["status"] == "OPEN":

                print(
                    f"{result['ip']:16} "
                    f"{result['port']:5}  "
                    f"{result['service']:15}  "
                    f"{result['latency']} ms"
                )

                if result["banner"]:

                    lines = result["banner"].splitlines()

                    print(
                    f"                  Banner: "
                    f"{lines[0]}"
                    )

                    for line in lines[1:]:

                        if line.strip():

                            print(
                                f"                          "
                                f"{line.strip()}"
                        )

    print("\n" + "=" * 65)
    print("                 SCAN COMPLETED! ")
    print("=" * 65)

# PROGRAM START
if __name__ == "__main__":
    main()
import ipaddress
import json
import re
import tempfile
from pathlib import Path
from subprocess import check_output

from karton.core import Karton, Resource, Task


def extract_ip(ip: str) -> str:
    if ":" in ip:
        return ip.split(":")[0]
    return ip


def convert_tlsmon(directory: Path) -> None:
    tlsmon_path = directory / "tlsmon.log"

    if not tlsmon_path.exists():
        return None

    data = tlsmon_path.read_text()
    output = []

    for line in data.splitlines():
        row = json.loads(line)
        master = row["master_key"]
        client = row["client_random"]
        output.append(f"CLIENT_RANDOM {client} {master}")

    (directory / "SSLKeysLogFile.txt").write_text("\n".join(output))


class KartonPcapMiner(Karton):
    """
    Extract network indicators from analysis PCAPs and add push them to MWDB as
    attributes
    """

    identity = "karton.pcap-miner"
    filters = [
        {
            "type": "analysis",
            "kind": "drakrun",
        }
    ]

    def select_nonlocal_ip(self, ip_a: str, ip_b: str) -> str:
        if ipaddress.ip_address(extract_ip(ip_a)) in self.vm_ip_range:
            return ip_b
        if ipaddress.ip_address(extract_ip(ip_b)) in self.vm_ip_range:
            return ip_a
        raise ValueError("Neither one of the IPs belong to the VM range")

    def parse_tcp_conv(self, output: str) -> list[str]:
        PAT = r"([\d.]+:\d+)\s+<->\s+([\d.]+:\d+)"
        matches = re.findall(PAT, output)

        results: set[str] = set()
        for source, destination in matches:
            results.add(self.select_nonlocal_ip(source, destination))

        return list(results)

    def parse_sni_output(self, output: str) -> list[str]:
        PAT = r"^(\S+)\s+(\d+)$"
        matches = re.findall(PAT, output)

        results: set[str] = set()
        for hostname, port in matches:
            results.add(f"{hostname}:{port}")

        return list(results)

    def default_parser(self, output: str) -> list[str]:
        return list(set(filter(None, output.splitlines())))

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # analysis VM range, used for detecting direction in connections
        self.vm_ip_range = ipaddress.ip_network(
            self.config.get("pcap-miner", "vm_ip_range", "10.0.0.0/8")
        )

        # do not report artifacts if number of results exceeds max_results
        self.max_results = self.config.getint("pcap-miner", "max_results", fallback=24)

        # do not analyze PCAP files exceeding this size
        self.max_pcap_size = self.config.getint("pcap-miner", "max_pcap_size")

        self.ignorelist = {}
        ignore_path = self.config.get("pcap-miner", "ignore_list")
        if ignore_path:
            self.ignorelist = json.loads(Path(ignore_path).read_text())
            self.log.info("Loaded ignorelist from %s", ignore_path)

        self.analyzers = {
            "network-http": (
                ["-T", "fields", "-e", "http.request.full_uri"],
                self.default_parser,
            ),
            "network-tcp": (["-z", "conv,tcp"], self.parse_tcp_conv),
            "network-sni": (
                [
                    "-Y",
                    'ssl.handshake.extension.type == "server_name"',
                    "-T",
                    "fields",
                    "-e",
                    "tls.handshake.extensions_server_name",
                    "-e",
                    "tcp.dstport",
                ],
                self.parse_sni_output,
            ),
            "network-dns": (
                ["-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"],
                self.default_parser,
            ),
        }

    def mine_pcap(self, directory: Path) -> dict[str, list[str]]:
        pcap_file = directory / "dump.pcap"
        ssl_keys_file = directory / "SSLKeysLogFile.txt"

        base_args = ["tshark", "-q", "-n", "-r", pcap_file.as_posix()]

        if ssl_keys_file.exists():
            base_args += ["-o", f"tls.keylog_file:{ssl_keys_file.as_posix()}"]

        results = {}

        for name, parser_data in self.analyzers.items():
            extra_args, parser = parser_data

            self.log.info("Executing %s", base_args + extra_args)
            output = check_output(base_args + extra_args).decode()
            results[name] = parser(output)

        return results

    def filter_results(self, results: dict[str, list[str]]) -> dict[str, list[str]]:
        output = {}
        for k, v in results.items():
            filter_list = self.ignorelist.get(k, [])
            filtered = [x for x in v if x not in filter_list]

            if self.max_results != -1 and len(filtered) > self.max_results:
                self.log.warning(
                    "Dropping results for %s due to high count: %s", k, len(filtered)
                )
            elif filtered:
                output[k] = sorted(filtered)

        return output

    def report_results(self, sample: Resource, results: dict[str, list[str]]) -> None:
        enrichment_task = Task(
            headers={
                "type": "sample",
                "stage": "analyzed",
            },
            payload={"sample": sample, "attributes": results},
        )
        self.send_task(enrichment_task)

    def process(self, task: Task) -> None:
        with tempfile.TemporaryDirectory() as dir_name:
            temp_dir = Path(dir_name)
            sample_id = task.get_payload("sample").sha256
            self.log.info("Handling sample [%s]", sample_id)

            pcap_file = task.get_payload("dump.pcap")
            tlsmon_log = task.get_payload("tlsmon.log")

            if not pcap_file:
                self.log.info("No PCAP file, nothing to do...")
                return

            if self.max_pcap_size and pcap_file.size > self.max_pcap_size:
                self.log.info(
                    "PCAP file size (%s) exceeds the configured limit (%s)",
                    pcap_file.size,
                    self.max_pcap_size,
                )
                return

            pcap_file.download_to_file(temp_dir / "dump.pcap")

            if tlsmon_log:
                self.log.info("tlsmon.log found, enabling TLS decryption")
                tlsmon_log.download_to_file(temp_dir / "tlsmon.log")
                convert_tlsmon(temp_dir)

            results = self.mine_pcap(temp_dir)
            results_filtered = self.filter_results(results)

            if results_filtered:
                self.log.info("Results:")
                for k, v in results_filtered.items():
                    self.log.info("%s: %s", k, len(v))
                self.report_results(
                    task.get_payload("sample"), results=results_filtered
                )

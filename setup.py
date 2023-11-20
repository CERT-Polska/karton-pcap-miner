#!/usr/bin/env python
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

from pathlib import Path

version_path = Path(__file__).parent / "karton/pcap_miner/__version__.py"
version_info = {}
exec(version_path.read_text(), version_info)

setup(
    name="karton-pcap-miner",
    version=version_info["__version__"],
    description="Extract network indicators from analysis PCAPs and add push them to MWDB as attributes",
    url="https://github.com/CERT-Polska/karton-pcap-miner/",
    long_description=open("README.md", "r").read(),
    long_description_content_type="text/markdown",
    namespace_packages=["karton"],
    packages=["karton.pcap_miner"],
    install_requires=open("requirements.txt").read().splitlines(),
    entry_points={
        "console_scripts": [
            "karton-pcap-miner=karton.pcap_miner:KartonPcapMiner.main"
        ],
    },
    classifiers=[
        "Programming Language :: Python",
        "Operating System :: OS Independent",
    ],
)

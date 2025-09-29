#!/usr/bin/env python3
"""
Setup script for SNB PCAP Analyzer
"""

from setuptools import setup, find_packages
import os

# Read the README file for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="snb-pcap-analyzer",
    version="1.0.0",
    author="SNB",
    description="Professional network traffic analysis tool for PCAP/PCAPNG files",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/SNB220/SNB-pcap-analyzer",
    project_urls={
        "Source Code": "https://github.com/SNB220/SNB-pcap-analyzer",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.0",
    ],
    extras_require={
        "full": [
            "requests>=2.25.0",
            "matplotlib>=3.3.0",
            "pandas>=1.3.0",
            "numpy>=1.20.0",
        ],
        "geo": ["requests>=2.25.0"],
        "viz": ["matplotlib>=3.3.0"],
    },
    entry_points={
        "console_scripts": [
            "snb-pcap-analyzer=pcap_analyzer:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "pcap", "network", "analysis", "security", "wireshark", 
        "traffic", "packets", "forensics", "monitoring", "scapy"
    ],
    zip_safe=False,
)

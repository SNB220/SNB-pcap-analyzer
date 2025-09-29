# SNB PCAP Analyzer - Example Usage

This directory contains example usage scenarios and sample outputs from SNB PCAP Analyzer.

## Example Files Structure

```
examples/
├── README.md                    # This file
├── sample_output.csv           # Example CSV output
├── sample_terminal_output.txt  # Example terminal output
└── usage_examples.md           # Common usage patterns
```

## Quick Examples

### Basic Analysis
```bash
python pcap_analyzer.py ../day1.pcapng
```

### Advanced Analysis with All Features
```bash
python pcap_analyzer.py -o detailed_report.csv ../day1.pcapng
```

### Fast Analysis (No Geolocation/Visualization)
```bash
python pcap_analyzer.py --no-geo --no-viz ../day1.pcapng
```

## Sample Analysis Results

The sample outputs in this directory were generated from a typical network capture containing:
- 813 packets over 3 minutes 20 seconds
- Mixed TCP/UDP/ARP/ICMP traffic
- HTTPS browsing activity
- DNS queries
- Local network communication

See the individual files for detailed examples of what SNB PCAP Analyzer can detect and analyze.
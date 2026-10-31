"""Run after CTest: python test/test_daemon_packet.py build/daemon_packet.bin"""
import contextlib
import io
from pathlib import Path
import struct
import sys
from unittest.mock import patch

from test_client import (HEADER_FMT, HEADER_SIZE, STATS_FMT, STATS_SIZE,
                         SSTDClient, format_daemon_usage)

packet = Path(sys.argv[1]).read_bytes()
header = struct.unpack(HEADER_FMT, packet[:HEADER_SIZE])
assert header[0] == 0x53535444 and header[2] == 0x11
assert header[-1] == STATS_SIZE == 138
body = packet[HEADER_SIZE:]
stats = struct.unpack(STATS_FMT, body)
assert stats[2] == 42 and stats[26] == 123456789
assert stats[27:] == (123, 65535)
assert format_daemon_usage(0) == '0.00%'
assert format_daemon_usage(1) == '0.01%'
assert format_daemon_usage(10000) == '100.00%'
assert format_daemon_usage(65535) == 'N/A'
output = io.StringIO()
with patch('os.system'), contextlib.redirect_stdout(output):
    SSTDClient.handle_system_stats(None, body)
assert 'SSTD CPU: 1.23% | MEM: N/A' in output.getvalue()
print('PASS: C++ packet decoded and displayed by Python receiver')

from zat.zeek_log_reader import ZeekLogReader
from typing import Tuple, List


def get_field_info(log_filename: str) -> Tuple[List[str], List[str]]:
    _zeek_reader = ZeekLogReader(log_filename)
    _, field_names, field_types, _ = _zeek_reader._parse_zeek_header(log_filename)
    return field_names, field_types

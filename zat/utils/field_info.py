from contextlib import contextmanager
from typing import Iterator, List, TextIO, Tuple


def _is_uri_path(log_filename: str) -> bool:
    return "://" in log_filename


@contextmanager
def _open_log_file(log_filename: str) -> Iterator[TextIO]:
    if not _is_uri_path(log_filename):
        with open(log_filename, "r") as log_file:
            yield log_file
        return

    try:
        import fsspec
    except ImportError as exc:
        raise ImportError(
            "Reading Zeek logs from URI paths requires fsspec. "
            "Install zat[s3] for S3 paths, or install the fsspec backend for this URI scheme."
        ) from exc

    with fsspec.open(log_filename, mode="rt") as log_file:
        yield log_file


def get_field_info(log_filename: str) -> Tuple[List[str], List[str]]:
    with _open_log_file(log_filename) as log_file:
        line = log_file.readline()
        while line and not line.startswith("#fields"):
            line = log_file.readline()

        if not line:
            raise ValueError("Could not find Zeek #fields header in {:s}".format(log_filename))

        field_names = line.strip().split("\t")[1:]
        line = log_file.readline()
        if not line.startswith("#types"):
            raise ValueError("Could not find Zeek #types header in {:s}".format(log_filename))
        field_types = line.strip().split("\t")[1:]

    return field_names, field_types


def test():
    import os

    import pytest

    from zat.utils import file_utils

    data_path = file_utils.relative_dir(__file__, "../../data")
    field_names, field_types = get_field_info(os.path.join(data_path, "conn.log"))
    assert field_names[:3] == ["ts", "uid", "id.orig_h"]
    assert field_types[:3] == ["time", "string", "addr"]

    try:
        import fsspec
    except ImportError:
        pytest.skip("pip install fsspec")

    remote_log = "memory://zat/test/conn.log"
    with fsspec.open(remote_log, "wt") as log_file:
        log_file.write(
            "#separator \\x09\n"
            "#set_separator\t,\n"
            "#empty_field\t(empty)\n"
            "#unset_field\t-\n"
            "#path\tconn\n"
            "#fields\tts\tuid\tid.orig_h\n"
            "#types\ttime\tstring\taddr\n"
            "1.0\tC1\t192.0.2.1\n"
            "#close\t2026-06-01-00-00-00\n"
        )

    field_names, field_types = get_field_info(remote_log)
    assert field_names == ["ts", "uid", "id.orig_h"]
    assert field_types == ["time", "string", "addr"]

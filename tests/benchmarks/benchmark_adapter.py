from casbin.persist.adapter import _extract_tokens


def _benchmark_extract_tokens(benchmark, line):
    @benchmark
    def run_benchmark():
        _extract_tokens(line)


def test_benchmark_extract_tokens_short_simple(benchmark):
    _benchmark_extract_tokens(benchmark, "abc,def,ghi")


def test_benchmark_extract_tokens_long_simple(benchmark):
    # fixed UUIDs for length and to be similar to "real world" usage of UUIDs
    _benchmark_extract_tokens(
        benchmark,
        "00000000-0000-0000-0000-000000000000,00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
    )


def test_benchmark_extract_tokens_short_nested(benchmark):
    _benchmark_extract_tokens(benchmark, "abc(def,ghi),jkl(mno,pqr)")


def test_benchmark_extract_tokens_long_nested(benchmark):
    _benchmark_extract_tokens(
        benchmark,
        "00000000-0000-0000-0000-000000000000(00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002),00000000-0000-0000-0000-000000000003(00000000-0000-0000-0000-000000000004,00000000-0000-0000-0000-000000000005)",
    )

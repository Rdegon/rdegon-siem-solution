from deploy import clickhouse_storage_io_profile as profile


def test_profile_limits_system_log_retention_and_query_profiling() -> None:
    assert "<level>warning</level>" in profile.SYSTEM_LOG_CONFIG
    assert "<log_processors_profiles>0</log_processors_profiles>" in profile.QUERY_PROFILING_CONFIG
    assert "<query_profiler_real_time_period_ns>0</query_profiler_real_time_period_ns>" in profile.QUERY_PROFILING_CONFIG
    assert set(profile.SYSTEM_LOG_TABLES) >= {
        "text_log",
        "processors_profile_log",
        "query_log",
        "part_log",
        "trace_log",
    }

add_unit_test(
    local_policy_mgmt_gen_ut
    "rate_limit_response_ut.cc;snort_conversion_ut.cc;policy_file_ut.cc;multiple_exceptions_ut.cc"
    "local_policy_mgmt_gen;logging;agent_core_utilities;crypto;messaging"
)

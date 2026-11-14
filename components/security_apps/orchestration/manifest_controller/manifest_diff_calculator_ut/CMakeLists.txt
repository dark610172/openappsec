add_unit_test(
    manifest_diff_calculator_ut
    "manifest_diff_calculator_ut.cc;../manifest_diff_calculator.cc;../../modules/package.cc"
    ""
)

# Bound regressions on the original implementation's dependency cycles.
set_tests_properties(manifest_diff_calculator_ut PROPERTIES TIMEOUT 15)

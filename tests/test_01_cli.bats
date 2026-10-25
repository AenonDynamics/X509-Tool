#!/usr/bin/env bats
# Tests for CLI: --help, --version, no args, invalid commands

load helpers

setup() {
    setup_test_workdir
}

teardown() {
    cleanup_test_workdir
}

@test "help flag shows usage" {
    run x509 --help
    assert_success
    assert_output_contains "Usage:"
    assert_output_contains "ca init"
    assert_output_contains "client add"
    assert_output_contains "server add"
    assert_output_contains "host add"
    assert_output_contains "code add"
    assert_output_contains "smime add"
    assert_output_contains "openvpn init"
}

@test "version flag shows version info" {
    run x509 --version
    assert_success
    assert_output_contains "x509-tool"
    assert_output_contains "Version:"
    assert_output_contains "MPL-2.0"
}

@test "no args shows usage" {
    run x509
    assert_success
    assert_output_contains "Usage:"
}

@test "invalid command shows usage" {
    # Note: show_usage calls exit 0, so invalid commands exit with 0
    run x509 frobnicate
    assert_success
    assert_output_contains "Usage:"
}

@test "invalid subcommand shows usage" {
    run x509 client frobnicate
    assert_success
    assert_output_contains "Usage:"
}

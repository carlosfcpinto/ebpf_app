#!/usr/bin/env bats


@test "eBPF block" {
    touch testfile

    # Set the file ownership to user with ID 1006
    chown 1006 testfile

    # Attempt to change the file mode as the user with ID 1006
    run su -c "chmod 777 testfile" -s /bin/bash test2

    rm testfile
    [ "$status" -ne 0 ]
}

@test "eBPF allows" {
    touch testfile2

    #testfile2 is whitelisted for user 1006 in ebpf program, so the chmod system call should be allowed
    chown 1006 testfile2
    run su -c "chmod 777 testfile2" -s /bin/bash test2

    rm testfile2
    [ "$status" -eq 0 ]
}

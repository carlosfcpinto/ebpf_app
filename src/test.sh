#!/usr/bin/env bats

create_user () {
    username=$1
    # Code block or Compound Commands
    if id "$username" &>/dev/null; then
        echo "User $username already exists."
        return 0
    fi
    useradd -m -s /bin/bash "$username"
    passwd -d "$username"
}

give_permission (){
    flag=$1
    username=$2
    if [ "$flag" = "yes" ]; then
        echo "uid: $(id -u $username)
directory:
    - $(pwd)/testfile2" > config.yaml
    fi
}

@test "Random" {
    create_user "test"
    give_permission "yes" "test"

    touch testfile2

    chown $(id -u test) testfile2

    run su -c "chmod 777 testfile2" -s /bin/bash test

    rm testfile2

    [ "$status" -eq 0 ]
}

@test "eBPF block" {
    touch testfile

    # Set the file ownership to user with ID 1006
    chown 1001 testfile

    # Attempt to change the file mode as the user with ID 1006
    run su -c "chmod 777 testfile" -s /bin/bash $(id -nu 1001)
    # run chmod 777 testfile

    rm testfile
    [ "$status" -ne 0 ]
}

@test "eBPF allows" {
    touch testfile2

    #testfile2 is whitelisted for user 1006 in ebpf program, so the chmod system call should be allowed
    chown 1001 testfile2
    run su -c "chmod 777 testfile2" -s /bin/bash $(id -nu 1001)
    # run chmod 777 testfile2

    rm testfile2
    [ "$status" -eq 0 ]
}

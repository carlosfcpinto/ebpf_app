#!/usr/bin/env bats

create_user () {
    username=$1
    if id "$username" &>/dev/null; then
        echo "User $username already exists."
        return 0
    fi
    sudo useradd -m $username
    sudo passwd -d $username > /dev/null
}

give_permission_rename (){
    flag=$1
    username=$2
    if [ $flag = 1 ]; then
        echo "uid: $(id -u $username)
directory:
    - $(pwd)
    - $(pwd)/testfile2" > config.yaml
else
        echo "uid: 1003 
directory:
    - $(pwd)
    - $(pwd)/testfile2" > config.yaml
    fi
}
give_permission (){
    flag=$1
    username=$2
    if [ $flag = 1 ]; then
        echo "uid: $(id -u $username)
directory:
    - $(pwd)/testfile2" > config.yaml
else
        echo "uid: 1003 
directory:
    - $(pwd)/testfile2" > config.yaml
    fi
}

# generator (){
#     username=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1)
#     permission=$((RANDOM % 2))
#     create_user $username
#     give_permission $permission $username
# }

@test "Random chmod" {
    username=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)
    permission=$((RANDOM % 2))
    # permission=0
    create_user $username
    give_permission $permission $username

    echo $permission > status.txt
    echo $username >> status.txt
    echo $(id -u $username) >> status.txt

    touch testfile2

    sudo chown $(id -u $username) testfile2

    ./eBPF_ls config.yaml &

    pid=$!

    echo $pid >> status.txt

    sleep 1s 3>&-

    run su -c "chmod 777 testfile2" -s /bin/bash $username

    echo $status >> status.txt

    kill $pid >> status.txt

    # echo "# this is getting here" >&3

    sudo rm testfile2

    sudo deluser --remove-home $username > /dev/null

    if [ $permission = 1 ];
    then
        [ "$status" -eq 0 ]
    else
        [ "$status" -ne 0 ]
    fi
}

@test "Random cat" {
    username=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)
    permission=$((RANDOM % 2))
    # permission=0
    create_user $username
    give_permission $permission $username

    echo $permission > status.txt
    echo $username >> status.txt
    echo $(id -u $username) >> status.txt

    touch testfile2

    sudo chown $(id -u $username) testfile2

    ./eBPF_ls config.yaml &

    pid=$!

    echo $pid >> status.txt

    sleep 1s 3>&-

    run su -c "cat testfile2" -s /bin/bash $username

    echo $status >> status.txt

    kill $pid >> status.txt

    # echo "# this is getting here" >&3

    sudo rm testfile2

    sudo deluser --remove-home $username > /dev/null

    if [ $permission = 1 ];
    then
        [ "$status" -eq 0 ]
    else
        [ "$status" -ne 0 ]
    fi
}

@test "Random mv" {
    username=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 10 | head -n 1)
    permission=$((RANDOM % 2))
    # permission=0
    create_user $username
    give_permission_rename $permission $username

    ./eBPF_ls config.yaml &
    sleep 1s 3>&-

    su $username
    cd

    touch testfile2
    sudo chown $(id -u $username) testfile2
    run su -c "mv testfile2 testfile" -s /bin/bash $username
    sudo rm testfile2

    exit

    echo $permission > status.txt
    echo $username >> status.txt
    echo $(id -u $username) >> status.txt


    pid=$!

    echo $pid >> status.txt



    echo $status >> status.txt

    kill $pid >> status.txt

    # echo "# this is getting here" >&3

    echo $status


    # sudo rm testfile

    sudo deluser --remove-home $username > /dev/null

    if [ $permission = 1 ];
    then
        [ "$status" -eq 0 ]
    else
        [ "$status" -ne 0 ]
    fi
}





#
# @test "eBPF block" {
#     touch testfile
#
#     # Set the file ownership to user with ID 1006
#     chown 1001 testfile
#
#     # Attempt to change the file mode as the user with ID 1006
#     run su -c "chmod 777 testfile" -s /bin/bash $(id -nu 1001)
#     # run chmod 777 testfile
#
#     rm testfile
#     [ "$status" -ne 0 ]
# }
#
# @test "eBPF allows" {
#     touch testfile2
#
#     #testfile2 is whitelisted for user 1006 in ebpf program, so the chmod system call should be allowed
#     chown 1001 testfile2
#     run su -c "chmod 777 testfile2" -s /bin/bash $(id -nu 1001)
#     # run chmod 777 testfile2
#
#     rm testfile2
#     [ "$status" -eq 0 ]
# }

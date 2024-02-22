# Not compiling ATM

Trouble passing strings from kernel to user space, maybe hash map should be of type string -> user, where string is the destination and we can flag directories so that only one user can modify them, unless the user making the call is whitelisted to be able to make it always.


# Requirements

Allow or deny the chmod system call, based on both the user and the directory where is being ran. We must assure that if a user is whitelisted then he will always be able to make the call. A directory can map a specific user that is not white listed to be able to make the chmod call inside it.

# Testing

The test.sh file is simplistic yet enough to show that the eBPF program is running. One test only, need to assemble a battery of them as to ensure that the application runs as expected.

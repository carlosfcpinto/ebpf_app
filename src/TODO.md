# Not compiling ATM

Trouble passing strings from kernel to user space, maybe hash map should be of type string -> user, where string is the destination and we can flag directories so that only one user can modify them, unless the user making the call is whitelisted to be able to make it always.

Can I map users to directories instead of directories to users? Seems like eBPF maps don't handle strings correctly, not being able to match on it in the expected manner.
UPDATE: Reading values correctly, assuming the max path provided is of size 100.

# Requirements

Allow or deny the chmod system call, based on both the user and the directory where is being ran. We must assure that if a user is whitelisted then he will always be able to make the call. A directory can map a specific user that is not white listed to be able to make the chmod call inside it.

Need 2 extra hookpoints to not allow calls to chown to certain files and to prevent users from using sudo su to a user with priviliges that can access them.

Map sudo calls to users who made it to prevent sudo su calls.

Prevent kill calls.

Freeze maps that store directories & users.

# Testing

The test.sh file is simplistic yet enough to show that the eBPF program is running. One test only, need to assemble a battery of them as to ensure that the application runs as expected.

We can use bats-core to do this, which is being ran right now. We will need the config from the yaml file to test the granular support for files.

Pass everything to github action, to test in the environment.

Property based testing, generate a smaller universe to test and generate tests to.

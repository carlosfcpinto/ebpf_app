# Not compiling ATM

Hook to the bpf_lsm_file_open security hookpoint, check the full path from struct path f_path inside struct file, read from an ebpf map to see if that file should be tracked or not, and allow or deny access based on it. The pidhid is useful to hide that the program is running to most users, should also be extended to hide normal files, not just numerical ones. 
These 3 programs in tandem should work correctly to prevent data exfiltration, should be finished by march 14th.

<!-- TODO: third bpf lsm program/ pidhide to hide normal folders/ program to prevent sudo calls/ bpf map freeze, to prevent updating maps while runnig the program, the configuratino should be static or allowed only to one user/ identify potential vulnerabilities. -->
# Requirements

Allow or deny the chmod system call, based on both the user and the directory where is being ran. We must assure that if a user is whitelisted then he will always be able to make the call. A directory can map a specific user that is not white listed to be able to make the chmod call inside it.

# Testing

The test.sh file is simplistic yet enough to show that the eBPF program is running. One test only, need to assemble a battery of them as to ensure that the application runs as expected.

We can use bats-core to do this, which is being ran right now. We will need the config from the yaml file to test the granular support for files.

Pass everything to github action, to test in the environment.

Property based testing, generate a smaller universe to test and generate tests to.

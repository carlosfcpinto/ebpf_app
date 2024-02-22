#!/bin/bash

# Create a test file
touch testfile

# Set the file ownership to user with ID 1006
chown 1006 testfile

# Attempt to change the file mode as the user with ID 1006
su -c "chmod 777 testfile" -s /bin/bash test2

# Check the exit status of the previous command
if [ $? -ne 0 ]; then
    echo "Test passed: User with ID 1006 cannot call chmod on the file"
else
    echo "Test failed: User with ID 1006 can call chmod on the file"
fi

# Clean up the test file
rm testfile

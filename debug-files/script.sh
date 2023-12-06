#!/bin/sh

echo "Machine stats:"
df -h
echo "-----"
free -h
echo "----"
>&2 echo "This message goes to stderr"
exit 0

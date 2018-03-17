#!/bin/bash
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECTDIR="$(dirname "$SCRIPTDIR")"
TESTCONF="$PROJECTDIR/build/testconfig.properties"
TESTLOG_A="$PROJECTDIR/build/test-after.log"
TESTLOG_B="$PROJECTDIR/build/test-before.log"

cd "$PROJECTDIR"

echo 'anonymizer=ipv4
' > "$TESTCONF"

cd "$PROJECTDIR/build/classes"
[ -d "java/main" ] && cd "java/main" || cd "main"

echo 'no ip address
1.1.172.3
123' > "$TESTLOG_B"

echo 'anonymizer=ipv4

ipv4.bits=16
ipv4.mode=zero' > "$TESTCONF"

java -Dconfigfile="$TESTCONF" com.rsyslog.slfa.Main "$TESTLOG_B" > "$TESTLOG_A"

echo 'no ip address
1.1.0.0
123' | cmp "$TESTLOG_A"
if [ ! $? -eq 0 ]; then
	echo "invalid response generated, $(basename "$TESTLOG_A") is:"
	echo '====='
	cat "$TESTLOG_A"
	echo '====='
	exit 1
fi

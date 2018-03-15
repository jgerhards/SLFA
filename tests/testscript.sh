#!/bin/bash
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECTDIR="$(dirname "$SCRIPTDIR")"
TESTCONF="$PROJECTDIR/build/testconfig.properties"
TESTLOG_A="$PROJECTDIR/build/test-after.log"
TESTLOG_B="$PROJECTDIR/build/test-before.log"


mkdir -p "$(dirname "$TESTCONF")"

cd "$PROJECTDIR"
./gradlew jar


$SCRIPTDIR/simple_test.sh

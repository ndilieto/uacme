#!/bin/sh
if test $# -ne "3" -o "x$1" != "x--upstream-version"; then
    echo "Usage: `basename $0` --upstream-version version filename"
    exit 1
fi

VERSION="$2"
FILENAME="$3"
BASENAME="$(basename $FILENAME)"
DELTA="https://raw.githubusercontent.com/ndilieto/uacme/pristine-tar/${BASENAME}.delta"

RC=0
OLDDIR=$(pwd)
WRKDIR=$(mktemp -d)
WRKFILE=$(mktemp)
if curl -s -o $WRKFILE $DELTA && tar zxf $FILENAME -C $WRKDIR --strip-components=1
then
    if cd $WRKDIR && pristine-tar gentar $WRKFILE $BASENAME && cd $OLDDIR
    then
        mv $WRKDIR/$BASENAME $FILENAME
    else
        RC=1
    fi
else
    RC=1
fi
rm -fr $WRKDIR $WRKFILE
if [ $RC -ne 0 ]
then
    rm -fr $FILENAME
    echo "`basename $0`: failed to process $FILENAME" 1>&2
fi
exit $RC

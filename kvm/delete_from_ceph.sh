#!/bin/bash

ARGS=1
E_BADARGS=65

if [ $# -ne $ARGS ]  # Correct number of arguments passed to script?
then
    echo "Usage: `basename $0` <template_name>"
    exit $E_BADARGS
fi

TEMPLATE=$1
rbd -p capacity snap unprotect ${TEMPLATE}@${TEMPLATE}_snap_selfdef
rbd -p capacity snap rm ${TEMPLATE}@${TEMPLATE}_snap_selfdef
rbd -p capacity rm ${TEMPLATE}

echo done
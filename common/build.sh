#!/bin/bash

# set -e
# set -x

currdir=`pwd`

init_submodule()
{
    git submodule init
    git submodule update --remote
}

build_dependlibs()
{
    if [ -f dependlibs/build.sh ]; then
        chmod +x dependlibs/build.sh
        cd dependlibs
        ./build.sh $1 $2 $3
        if [ $? -eq 1 ]; then
            echo "build dependlibs error."
            cd $currdir
            return 1
        else
            cd $currdir
            return 0
        fi
    fi
    return 0
}

run()
{
    # init git submodule
    init_submodule
    # build dependlibs
    build_dependlibs $1 $2 $3
    if [ $? -eq 0 ]; then
        if [ "$1"x == "clean"x ]; then
            make clean
        else
            make
        fi
    fi
}

run $1 $2 $3
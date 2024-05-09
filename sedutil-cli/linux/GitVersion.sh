#!/bin/bash 
set -x
GIT=`which git`
SFX_VER="2.00-sfx"
if [ "x"${GIT} == "x" ]; then
        echo "#define GIT_VERSION \"$SFX_VER\""
else
        #GITVER=`git describe --dirty`
        echo "#define GIT_VERSION " \"$SFX_VER\"
fi

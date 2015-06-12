#!/usr/bin/env bash
#
# Copyright (c) 2015, Verisign, Inc.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of tlsa-survey nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set -e

if test $# -lt 1 ; then
	echo "usage: $0 input" 1>&2
	exit 1
fi
INPUT=$1 ; shift

DATE=`date +%Y-%m-%d`
SCRIPT_DIR=`dirname $0`
DATA_DIR="data"
mkdir -p $DATA_DIR
DB="$DATA_DIR/stats.$DATE.db"
THREAD_NUM="20"
NSSERVER=$2

# script to get server certs using openssl
CERT_SCRIPT="$SCRIPT_DIR/get_serv_cert.sh"

cat $INPUT | python $SCRIPT_DIR/tlsa_survey.py -d -s $NSSERVER:53 -t $THREAD_NUM -o $DB -c $CERT_SCRIPT

# get tlsa zone and dnssec zone number
python $SCRIPT_DIR/dnssec_tlsa_zone_num.py -i $DATA_DIR/dnssec_tlsa_zone_num.db -d $DATE -n 0 -p $SCRIPT_DIR

echo "tlsa survey is successful for $DATE" 1>&2
exit 0

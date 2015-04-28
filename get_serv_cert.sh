#!/usr/bin/env bash

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

echoerr() { echo -e "$@" 1>&2; }
usage() {
    #echoerr "[error] arguments are required"
    echoerr "example: $0 -n google.com -p 443 [-s google.com] [-a] [-h 1.2.3.4] [-4] [-6]"
}
cmd_exists () { type "$1" &> /dev/null; }

# -servername is needed for SNI, otherwise,
# some certs are different from ones from brower

# need a timeout for openssl
TIMEOUT_NUM=20
TIMEOUT_COM=timeout
OS=`uname -s`
if [ "$OS" == "Darwin" ] ; then
    TIMEOUT_COM=gtimeout
fi

PORT_NUM=""
CONN_NAME=""
SERV_NAME=""
SHOW_CERTS=""
HOST_IP=""
while getopts ":n:p:s:h:a" opt; do
    case $opt in
	n)
	    CONN_NAME=$OPTARG
	    ;;
	p)
	    PORT_NUM=$OPTARG
	    ;;
	s)
	    SERV_NAME=$OPTARG
	    ;;
	h)
	    HOST_IP=$OPTARG
	    ;;
	a)
	    SHOW_CERTS="-showcerts"
	    ;;
	\?)
	    echo "Invalid option: -$OPTARG" >&2
	    exit 1
	    ;;
	:)
	    echo "Option -$OPTARG requires an argument." >&2
	    exit 1
	    ;;
    esac
done

if [ -z $PORT_NUM ] ; then
    echoerr "[error] a port number must be given, abort!"
    usage
    exit 1
fi

if [ -z $CONN_NAME ] && [ -z $HOST_IP ] ; then
    echoerr "[error] a domain name or IP address must be given, abort!"
    usage
    exit 1
fi

SNI_EXT=""
if [ ! -z $SERV_NAME ] ; then
    SNI_EXT="-servername $SERV_NAME"
fi

#echo "serv_name = $SERV_NAME"
#echo "port_num  = $PORT_NUM"
#echo "conn_name = $CONN_NAME"
#echo "sni_ext   = $SNI_EXT"

OPENSSL_COM=""
if [ ! -z $HOST_IP ] ; then
    OPENSSL_COM="openssl s_client -host $HOST_IP -port $PORT_NUM"
else
    # must have CONN_NAME, get IPv4 only, otherwise with -connect $name:$port, 
    # ipv6 may be used and it's possible that ipv4 cert and ipv6 cert are different
    IPaddr=`dig $CONN_NAME A +short | sed -n '/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/p' | sed -n '1p'`
    echoerr "IPaddr[$IPaddr]"
    OPENSSL_COM="openssl s_client -host $IPaddr -port $PORT_NUM"
fi

STARTTLS=""
if [ "$PORT_NUM" == "587" ] || [ "$PORT_NUM" == "25" ] ; then
    STARTTLS="-starttls smtp"
fi

if cmd_exists $TIMEOUT_COM ; then
    echo -n | $TIMEOUT_COM $TIMEOUT_NUM $OPENSSL_COM $STARTTLS $SNI_EXT $SHOW_CERTS | \
	sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
else
    echo -n | perl -e "alarm $TIMEOUT_NUM;exec @ARGV" $OPENSSL_COM $STARTTLS $SNI_EXT $SHOW_CERTS | \
	sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
fi
exit 0

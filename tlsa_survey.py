#!/usr/bin/env python

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

import sys, os, subprocess, getopt
import ssl, M2Crypto, socket, hashlib
import dns.resolver
import datetime, time, calendar, sqlite3
import Queue, threading

def hexdump(str, separator=''):
    return separator.join(x.encode('hex') for x in str)

def fmt_str(s):
    s = s.replace(' ','')
    return s.upper()

def print_err(s):
    sys.stderr.write(s)

def run_bash(c):
    p = subprocess.Popen(c.split(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    output, err = p.communicate()
    return output

def tlsa_select(s, cert):
    if s == 0:
        return cert.as_der()
    elif s == 1:
        return cert.get_pubkey().as_der()
    else:
        sys.exit('[error] selector[%d] is not valid\n' % s)

def tlsa_match(mtype, cert_data, from_dns, err_msg, idx):
    hex_data = hexdump(cert_data)
    if mtype == 1:
        hex_data = hashlib.sha256(cert_data).hexdigest()
    elif mtype == 2:
        hex_data = hashlib.sha512(cert_data).hexdigest()
    elif mtype != 0:
        sys.exit('[error] mathing type[%s] is not valid\n' % mtype)
    if fmt_str(hex_data) == fmt_str(from_dns):
        return True
    else:
        err_msg[idx] = '# from cert:%s\n# from DNS: %s' % (fmt_str(hex_data), fmt_str(from_dns))
        return False

def is_valid(certs, tlsa_ans, err_msg, idx):
    cert_usage = tlsa_ans.usage
    selector = tlsa_ans.selector
    mtype = tlsa_ans.mtype
    if not (cert_usage in [0,1,2,3] and selector in [0,1] and mtype in [0,1,2]):
        err_msg['BAD-PARA'] = True
        print_err('[error] parameters are not valid\n')
        return False
    ct = hexdump(tlsa_ans.cert)
    if cert_usage in [0, 2]: # need to find one trust anchor, loop all
        for cert in certs:
            cert_obj = M2Crypto.X509.load_cert_string(cert)
            cert_data = tlsa_select(selector, cert_obj)
            if tlsa_match(mtype, cert_data, ct, err_msg, idx):
                return True
    elif cert_usage in [1, 3]:
        cert_obj = M2Crypto.X509.load_cert_string(certs[0])
        cert_data = tlsa_select(selector, cert_obj)
        if tlsa_match(mtype, cert_data, ct, err_msg, idx):
            return True
    else:
        sys.exit('[error] cert_usage[%d] is not valid\n' % cert_usage)
    return False

def rm_last_dot(s):
    if len(s) > 1 and s.endswith('.'):
        return s[:-1]
    return s

def get_tld(n):
    n = rm_last_dot(n)
    w = n.split('.')
    if len(w) == 0:
        sys.exit('[error] cannot get tld for [%s]' % n)
    if len(w) == 1:
        return n
    return w[-1]

def split_certs(multi_certs):
    cert_list = []
    certs = multi_certs.split('-----END CERTIFICATE-----')
    for cert in certs:
        if len(cert) == 0 or cert == '\n':
            continue
        cert_list.append(cert + '-----END CERTIFICATE-----')
        #print cert_list[-1]
    return cert_list

def get_utc_sec():
    return calendar.timegm(datetime.datetime.utcnow().timetuple())
 
#global var
db_lock = None
sqldb = None
sqldb_cur = None
is_debug = False
serv_port = 53
serv_ip = ''
this_date = None
TABLE_NAME = None
TIMESTAMP = None # the start time of this script, used to identify the probing round
cert_script = '' 

def get_cert(name, port, serv_name):
    global cert_script
    if not os.path.isfile(cert_script):
        sys.exit('[error] cert_script[%s] does not exist, abort!' % cert_script)
    #remove last '.', otherwise openssl cannot get cert for unknown reason
    name = rm_last_dot(name)
    serv_name = rm_last_dot(serv_name)
    try:
        sni_ext = ''
        if len(serv_name) != 0:
            sni_ext = '-s %s' % serv_name
        certs = run_bash('%s -n %s -p %d %s -a' % (cert_script, name, port, sni_ext))
        cert_list = split_certs(certs)
        if len(cert_list) == 0: 
            return None
        else:
            return cert_list
    except:
        print_err("#Unexpected error: %s\n" % str(sys.exc_info()))
        return None

def send_query(resolver, qname, type, myid):
    global is_debug, serv_ip, serv_port
    resolver.timeout = 5    # default is 2
    resolver.lifetime = 10   # default is 30
    if is_debug:
        print_err('[%d] send query %s[%s]\n' % (myid, qname, type))
    if serv_ip != '': # just double check,serv_ip may be kicked out if a server failure
        #resolver = dns.resolver.Resolver(configure=False)
        resolver.port = serv_port
        resolver.nameservers = [serv_ip]
    try:
        answers = resolver.query(qname, type)
        if is_debug:
            print_err('[%d] has ans for %s[%s]\n' % (myid, qname, type))
        return answers
    except dns.resolver.NXDOMAIN:
        if is_debug:
            print_err('[%d] NXDOMAIN: %s[%s]\n' % (myid, qname, type))
        return None
    except dns.resolver.Timeout:
        if is_debug:
            print_err('[%d] Timeout: %s[%s]\n' % (myid, qname, type))
        return None
    except dns.resolver.NoAnswer:
        if is_debug:
            print_err('[%d] NoAnswer: %s[%s]\n' % (myid, qname, type))
        return None
    except:
        if is_debug:
            print_err('[%d] Other exception: %s[%s]: %s\n' % (myid, qname, type, sys.exc_info()))
        return None

def write_db(qn, port, tlsa_ans, valid_info):
    global sqldb, sqldb_cur, db_lock, TABLE_NAME, this_date, TIMESTAMP
    tmp_tld = None
    qn = rm_last_dot(qn)
    for rdata in tlsa_ans:
        ct = hexdump(rdata.cert)
        tmp_tld = get_tld(qn)
        sql_stat = "INSERT INTO %s VALUES (\'%s\', %d, %d, %d, %d, \'%s\',%d,\'%s\',%d,%d,%d,\'%s\')" % (TABLE_NAME, tmp_tld, this_date.year, this_date.month, this_date.day, TIMESTAMP, qn, port, valid_info, rdata.usage, rdata.selector,rdata.mtype,ct)
        with db_lock:
	    try:
            	sqldb_cur.execute(sql_stat)
            	sqldb.commit()
	    except sqlite3.IntegrityError:
		sqldb.rollback()

def validator(qn, port, resolver, tlsa_ans, myid):
    global is_debug
    # check if there is *A* record, if not, openssl cannot get cert
    # since IPv6 is not widely used, only validate IPv4 here. TODO: IPv6
    ipv4_ans = send_query(resolver, qn, 'A', myid)
    valid_info='EMPTY'
    if ipv4_ans == None:
        valid_info='NO-IP'
        write_db(qn, port, tlsa_ans, valid_info)
        return
        
    norm_cert = get_cert(qn, port, '')
    sni_cert = get_cert(qn, port, qn)

    # check if openssl can get certs or not
    # print cert info, none, one or both
    cert_info = ''
    if sni_cert != None:
        cert_info += '[sni]'
    if norm_cert != None:
        cert_info += '[norm]'
    if cert_info != '':
        print_err('[%d] [info] %s cert found, %s:[%d]\n' % (myid, cert_info, qn, port))
    else: # no certs, no validation
        print_err('[warn] NO-CERT found, %s:[%d]\n' % (qn, port))
        valid_info='NO-CERT'
        write_db(qn, port, tlsa_ans, valid_info)
        return

    # check if it has TLSA, input might be out of date
    if tlsa_ans == None:
        valid_info='NO-TLSA'
        write_db(qn, port, tlsa_ans, valid_info)
        return

    # Now, it has certs and TLSA, then just check if there is a match
    err_msg = {}
    sni_cert_ok = False
    norm_cert_ok = False
    for rdata in tlsa_ans:
        sni_cert_ok = False
        norm_cert_ok = False
        
        if sni_cert != None:
            sni_cert_ok = is_valid(sni_cert, rdata, err_msg, 'sni')
        if norm_cert != None:
            norm_cert_ok = is_valid(norm_cert, rdata, err_msg, 'norm')
            
        cert_info = ''
        if sni_cert_ok:
            cert_info += '[sni]'
            valid_info = 'OK'
        if norm_cert_ok:
            cert_info += '[norm]'
            valid_info = 'OK'
        if cert_info != '':
            print_err('[%d] [info] %s cert matches! %s:[%d]\n' % (myid, cert_info, qn, port))
        else: #if not sni_cert_ok and not norm_cert_ok:
            if valid_info == 'EMPTY':
                if 'BAD-PARA' in err_msg:
                    valid_info = 'BAD-PARA'
                else:
                    valid_info = 'BAD-HASH'
            print_err('[%d] [info] no cert matches, %s:[%d]\n' % (myid, qn, port))
            if 'sni' in err_msg:
                print_err('# SNI\n' + err_msg['sni']+'\n')
            if 'norm' in err_msg:
                print_err('# Norm\n' + err_msg['norm'] + '\n')
    
    write_db(qn, port, tlsa_ans, valid_info)

def fmt_tlsa_name(s, port):
    return '_' + str(port) + '._tcp.' + s


def tlsa_query(qn, port, resolver, myid):
    qn = rm_last_dot(qn);
    tlsa_name = fmt_tlsa_name(qn, port)
    answers = send_query(resolver, tlsa_name, 'TLSA', myid)
    if answers != None:
	validator(qn, port, resolver, answers, myid)

class SurveyThread(threading.Thread):
    def __init__(self, queue, myid, arg):
        threading.Thread.__init__(self)
        self.queue = queue
        self.myid = myid
        self.arg = arg
        #self.serv_ip = arg['serv_ip']
        #self.serv_port = arg['serv_port']
        if arg['serv_ip'] != '':
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.port = arg['serv_port']
            self.resolver.nameservers = [arg['serv_ip']]
        else:
            self.resolver = dns.resolver.Resolver()

    def run(self):
        arg = self.arg
        #resolver = self.resolver
        while True:
            qn = self.queue.get()
            qn = rm_last_dot(qn)
	    print_err('qn=' + qn + '\n')
            # send TLSA
            # if yes, then validate and write to sql file

            # WWW/HTTPS
	    tlsa_query(qn, 443, self.resolver, self.myid);
            tlsa_query('www.' + qn, 443, self.resolver, self.myid)

            # SMTP
            mx_ans = send_query(self.resolver, qn, 'MX', self.myid)
            if mx_ans != None: # has mx, query _NNN._tcp.$MXNAME
                for rdata in mx_ans:
		    for port in [25, 587, 465]:
                    	tlsa_query(str(rdata.exchange), port, self.resolver, self.myid)
            else: # no mx, query _NNN._tcp.$ZONE    
		for port in [25, 587, 465]:
                    tlsa_query(qn, port, self.resolver, self.myid)

            # JABBER/XMPP
	    for srv_qn in [ '_xmpp-client._tcp.' + qn, '_xmpp-server._tcp.' + qn ]:
            	srv_ans = send_query(self.resolver, srv_qn, 'SRV', self.myid)
		if srv_ans != None:
		    for rdata in srv_ans:
			tlsa_query(str(rdata.target), rdata.port, self.resolver, self.myid)
            else: # no SRV, look for {xmpp,jabber}.$ZONE
		for x_qn in ['jabber.' + qn, 'xmpp.' + qn]:
		    for port in [5222, 5269]:
                    	tlsa_query(x_qn, port, self.resolver, self.myid)

                #time.sleep(0.01) #do NOT send too fast
            print_err('[%d] DONE-ONE\n' % self.myid)
            sys.stderr.flush()
            self.queue.task_done()

def tlsa_survey(in_fn, serv_ip, serv_port, num_threads):
    global is_debug
    f = sys.stdin
    if in_fn != '-':
        f = open(in_fn,'r')
    queue = Queue.Queue()
    arg = {'debug':False, 'serv_ip':'', 'serv_port':'53'}
    arg['serv_ip'] = serv_ip
    arg['serv_port'] = serv_port
    for i in range(num_threads):
        t = SurveyThread(queue, i, arg)
        t.setDaemon(True)
        t.start()
    for l in f:
        if len(l) == 0 or l[0] == '#' or l == '\n':
            continue
        l = l.strip()
        if is_debug:
            print_err('[main]: %s\n' % l)
        queue.put(l)
    queue.join()
    if in_fn != '-':
        f.close()

def tlsa_only_validation(in_fn, serv_ip, serv_port):
    global is_debug
    resolver = dns.resolver.Resolver(configure=False)
    resolver.port = serv_port
    resolver.nameservers = serv_ip

    base_name = os.path.basename(in_fn)
    in_path = os.path.dirname(in_fn)
    start_date = base_name.split('.')[1] #stats.2014-08-01.hostname.db
    dy_str, dm_str, dd_str = start_date.split('-')
    select_db = sqlite3.connect(in_fn)
    select_cur = select_db.cursor()
    rows = select_cur.execute('select distinct name, port from tlsa_rdata where year=%s and month=%s and day=%s' % (dy_str, dm_str, dd_str))
    have_tlsa = 0
    done_rows = 0
    for row in rows:
        done_rows += 1
        qn = row[0]
        port = int(row[1])
        tlsa_name = fmt_tlsa_name(qn, port)
        answers = send_query(resolver, tlsa_name, 'TLSA', 1)
        if answers != None:
            have_tlsa += 1
            validator(qn, port, resolver, answers, 1)
    if done_rows != have_tlsa:
        print_err('[error] done_rows[%d] != have_tlsa[%d] for %s \n' % (done_rows,have_tlsa, in_fn))
    select_cur.close()
    select_db.close()
                
def usage(comm):
    print 'usage: %s [-htsioc]' % comm
    print '\t -h           print this message'
    print '\t -t  NUM      # of threads, default 10'
    print '\t -s  IP:PORT  server ip and port, like 1.2.3.4:53'
    print '\t              otherwise, using default DNS server'
    print '\t -i  INPUT    input file, default is - (stdin)'
    print '\t -o  OUTPUT   output file, default is ./stats.db'
    print '\t -c  SCRIPT   a script to get server certs'
    print '\t              default is ./get_serv_cert.sh'
    print '\t -v           only do validation, only work'
    print '\t              with input $X.$YEAR-$MONTH-$DAY.$Y.$Z'

def get_serv(s):
    if not ':' in s:
        print_err('[error] -s must have argument like 1.2.3.4:53\n')
        sys.exit(1)
    w = s.split(':')
    return (w[0], int(w[1]))

def init():
    global this_date, sqldb, sqldb_cur, db_lock, is_debug, serv_port, serv_ip, TABLE_NAME, TIMESTAMP
    this_date = datetime.datetime.now()
    sqldb = None
    sqldb_cur = None
    db_lock = threading.Lock()
    is_debug = False
    serv_port = 53
    serv_ip = ''
    TABLE_NAME = 'tlsa_rdata'
    TIMESTAMP = get_utc_sec()

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hdvt:s:i:o:c:', ['help', 'debug', 'valid', 'threads=', 'server=', 'input=', 'output=', 'cert='])
    except getopt.GetoptError as err:
        print_err(str(err) + '\n')
        usage(sys.argv[0])
        sys.exit(1)

    num_threads = 10
    in_fn = '-'
    out_fn = './stats.db'
    init()
    global sqldb, sqldb_cur, is_debug, serv_ip, serv_port, TABLE_NAME, cert_script
    cert_script = './get_serv_cert.sh'
    only_validation = False
    for o, a in opts:
        if o in ('-h', '--help'):
            usage(sys.argv[0])
            sys.exit()
        elif o in ('-t', '--threads'):
            num_threads = int(a)
        elif o in ('-s', '--server'):
            (serv_ip, serv_port) = get_serv(a)
        elif o in ('-i', '--input'):
            in_fn = a
        elif o in ('-d', '--debug'):
            is_debug = True
        elif o in ('-o', '--output'):
            out_fn = a
        elif o in ('-c', '--cert'):
            cert_script = a
        elif o in ('-v', '--valid'):
            only_validation = True

    if is_debug:
        print_err('serv_ip[%s], serv_port[%d], input[%s], output[%s], threads[%d], cert_script[%s]\n' % (serv_ip if serv_ip != '' else 'default', serv_port, in_fn, out_fn, num_threads, cert_script))
    if in_fn != '-' and not os.path.isfile(in_fn):
        sys.exit('[error] input file %s does not exist!' % in_fn)

    if not os.path.isfile(cert_script):
        sys.exit('[error] cert_script[%s] does not exist, abort!' % cert_script)
    
    sqldb = sqlite3.connect(out_fn, check_same_thread=False)
    sqldb_cur = sqldb.cursor()
    sql_stat = "CREATE TABLE if not exists " + TABLE_NAME + " (zone text, year int, month int, day int, timestamp, name text, port int, valid_info text, cert_usage int, selector int, mtype int, cert_info);"
    sqldb_cur.execute(sql_stat)
    sql_stat = "CREATE UNIQUE INDEX if not exists " + TABLE_NAME + "_uniq ON " + TABLE_NAME + "(zone, year, month, day, timestamp, name, port, valid_info, cert_usage, selector, mtype, cert_info);"
    sqldb_cur.execute(sql_stat)
    sqldb.commit()
    print_err('start @ ' + str(datetime.datetime.now()) + '\n')
    if only_validation:
        print_err('[warn] only validation!\n')
        tlsa_only_validation(in_fn, serv_ip, serv_port)
    else:
        tlsa_survey(in_fn, serv_ip, serv_port, num_threads)
    print_err('end @ ' + str(datetime.datetime.now()) + '\n')
    sqldb.close()

if __name__ == "__main__":
    main()

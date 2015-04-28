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

import sqlite3, getopt, datetime, os, sys, calendar, subprocess, bz2
from datetime import date, timedelta

def print_err(s):
    sys.stderr.write(s)

def run_bash(c):
    p = subprocess.Popen(c.split(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    output, err = p.communicate()
    return output

def validate(d):
    try:
        datetime.datetime.strptime(d, '%Y-%m-%d')
    except ValueError:
        return False
    return True

def get_date(dy, dm, dd, num_days):
    start_date = datetime.date(dy, dm, dd)
    rv = start_date + timedelta(days = num_days)
    return rv

def rm_last_dot(s):
    if len(s) > 1 and s.endswith('.'):
        return s[:-1]
    return s

def get_zone(n):
    n = rm_last_dot(n)
    w = n.split('.')
    if len(w) == 0:
        sys.exit('[error] cannot get zone for [%s]' % n)
    if len(w) == 1:
        return n
    if len(w) > 1:
        return w[-2] + '.' + w[-1]

def get_tld(n):
    n = rm_last_dot(n)
    w = n.split('.')
    if len(w) == 0:
        sys.exit('[error] cannot get tld for [%s]' % n)
    if len(w) == 1:
        return n
    return w[-1]

def get_line_num(fn):
    if not os.path.isfile(fn):
        sys.exit('[error] file[%s] does not exist, abort!' % fn)
    input_file = None
    if fn.endswith('.bz2'):
        input_file = bz2.BZ2File(fn, 'rb')
    else:
        input_file = open(fn, 'r')
    line_num = 0
    try:
        for l in input_file:
            l = l.strip()
            if len(l) == 0 or l[0] == '#' or l == '\n':
                continue
            line_num += 1
    finally:
        input_file.close()
    return line_num

def usage(comm):
    global plot_type_list
    print 'usage: %s [-hiodna]' % comm
    print '\t -h                print this message'
    print '\t -i  INPUT FILE    input file, only for -a insert'
    print '\t -p  INPUT PATH    input path'
    print '\t -d  YYYY-MM-DD    select Date'
    print '\t -n  NUMBER        number of days, must be a positive integer'
    print '\t -z  SELECT ZONE   zone name, used as input prefix'
    print '\t                   process all zone in db if empty'

def insert_zone_db(in_path, in_fn, date_text, num_days, zone):
    sql_stat = ''
    if not os.path.isfile(in_fn):
        print_err('[warn] create %s\n' % in_fn)
        new_sqldb = sqlite3.connect(in_fn)
        new_sqldb_cur = new_sqldb.cursor()
        sql_stat = "CREATE TABLE if not exists zone_num (zone text, year int, month int, day int, tlsa_name int, tlsa_zone int, dnssec_zone int)"
        new_sqldb_cur.execute(sql_stat)
        new_sqldb.commit()
        new_sqldb_cur.close()
        new_sqldb.close()

    sqldb = sqlite3.connect(in_fn)
    sqldb_cur = sqldb.cursor()

    dy_str, dm_str, dd_str = date_text.split('-')
    dy = int(dy_str)
    dm = int(dm_str)
    dd = int(dd_str)        
    total_name = 0
    total_dnssec = 0
    top_zone = {}
    level2_zone = {}
    tmp_lev2_zone = ''
    tmp_top_zone = ''
    for x in range(0, 1 + num_days):
        select_date = str(get_date(dy, dm, dd, x))
        select_date_1 = str(get_date(dy, dm, dd, x - 1))
        dy_str_tmp, dm_str_tmp, dd_str_tmp = select_date.split('-')
        dy_str_tmp_1, dm_str_tmp_1, dd_str_tmp_1 = select_date_1.split('-')
        conn = sqlite3.connect(in_path + '/data/stats.%s.db' % select_date)
        c = conn.cursor()
        base_select = 'select distinct name, port, zone from tlsa_rdata where year=%s and month=%s and day=%s' % (dy_str_tmp,
                                                                                                                  dm_str_tmp,
                                                                                                                  dd_str_tmp)
        if zone == '':
            sql_stat = 'select distinct name from (%s)' % base_select
        else:
            sql_stat = 'select distinct name from (%s) where zone=\'%s\'' % (base_select, zone)
        level2_zone.clear()
        top_zone.clear()
        c.execute(sql_stat)
        for row in c:
            n = row[0]
            tmp_lev2_zone = get_zone(n)
            tmp_top_zone = get_tld(n)
            if not tmp_lev2_zone in level2_zone: #check uniq level 2 zone
                level2_zone[tmp_lev2_zone] = 1
                if not tmp_top_zone in top_zone:
                    top_zone[tmp_top_zone] = 0
                top_zone[tmp_top_zone] += 1 # count the total number of uniq TLSA enabled level 2 zone, based on gTLD
        for z, zc in top_zone.iteritems():
            sql_stat = 'select count(*) from (select distinct name, port from (%s) where zone=\'%s\')' % (base_select,z)
            c.execute(sql_stat)
            total_name = -1
            total_name = c.fetchone()[0]
            ds_name_file = in_path + '/input/' + z + '-signed-zones-' + dy_str_tmp_1 + dm_str_tmp_1 + dd_str_tmp_1 + '.bz2'
            total_dnssec = -1 #-1 means files does not exist
            if os.path.isfile(ds_name_file):
                total_dnssec = get_line_num(ds_name_file)
            print_err('%s: zone[%s] tlsa_name[%d] tlsa_zone[%d] dnssec_zone[%d]\n' % (select_date_1,
                                                                                      z,
                                                                                      total_name, 
                                                                                      zc, 
                                                                                      total_dnssec))
            sqldb_cur.execute("INSERT INTO zone_num VALUES (\'%s\', %s, %s, %s, %d, %d, %d)" % (z,
                                                                                                dy_str_tmp_1, 
                                                                                                dm_str_tmp_1,
                                                                                                dd_str_tmp_1,
                                                                                                total_name, 
                                                                                                zc, 
                                                                                                total_dnssec))
            sqldb.commit()

        c.close()
        conn.close()
    
    sqldb_cur.close()
    sqldb.close()

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hi:p:d:n:z:H:', ['help', 'input=', 'path=', 'date=', 'numdays=', 'zone='])
    except getopt.GetoptError as err:
        print_err(str(err) + '\n')
        usage(sys.argv[0])
        sys.exit(1)
    in_path   = ''
    date_text = ''
    in_fn     = ''
    action    = ''
    zone      = ''
    num_days  = -1
    for o, a in opts:
        if o in ('-h', '--help'):
            usage(sys.argv[0])
            sys.exit()
        elif o in ('-d', '--date'):
            date_text = a
        elif o in ('-i', '--input'):
            in_fn = a
        elif o in ('-p', '--path'):
            in_path = a
        elif o in ('-z', '--zone'):
            zone = a
        elif o in ('-n', '--numdays'):
            num_days = int(a)

    if date_text == '':
        usage(sys.argv[0])
        sys.exit('[error] date must be provided, abort!')
    elif not validate(date_text):
        sys.exit('[error] date is not valid, abort!')

    if num_days < 0:
        usage(sys.argv[0])
        sys.exit('[error] num_days[%d] < 0, abort!' % num_days)

    if in_path == '':
        usage(sys.argv[0])
        sys.exit('[error] input path is empty, abort!')
    elif not os.path.isdir(in_path):
        sys.exit('[error] input path does not exist, abort!')

    if in_fn == '':
        usage(sys.argv[0])
        sys.exit('[error] input file is empty, abort!')

    insert_zone_db(in_path, in_fn, date_text, num_days, zone)

if __name__ == "__main__":
    main()

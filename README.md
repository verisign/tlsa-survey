
This is a set of scripts written to conduct surveys of TLSA records in
the DNS.

This code was initially written and developed by Liang Zhu of UCS/ISI
and Duane Wessels of Verisign Labs.

Dependencies:

    - Python
    - sqlite3
    - dnspython
 

Usage:

    $ sh tlsa_survey.sh list-of-domains name-server

    Where list-of-domains is a text file containing domains to be tested
    for the presence of TLSA records and name-server is a resolver DNS server name or IP.
    
Operation:    

    For each input domain, the script issues queries for names most
    likely to have associated TLSA records.  These include:

    # https
    _443._tcp.$domain
    _443._tcp.www.$domain

    # smtp if $domain has MX record
    _25._tcp.mxname($domain)
    _587._tcp.mxname($domain)
    _465._tcp.mxname($domain)

    # smtp without MX record
    _25._tcp.$domain
    _587._tcp.$domain
    _465._tcp.$domain

    # jabber/xmpp if $domain has SRV record
    srvname(_xmpp-client._tcp.$domain)
    srvname(_xmpp-server._tcp.$domain)

    # jabber/xmpp without SRV record
    _5222._tcp.jabber.$domain
    _5269._tcp.jabber.$domain
    _5222._tcp.xmpp.$domain
    _5269._tcp.xmpp.$domain

    Results of the survey are placed into an sqlite3 database.
    
Validation:    

    This code validates if the TLSA record matches the certificate
    received from server based on the cert usage, selector and
    matching type in TLSA records. (Usage 0 is not verified since it
    may constrain the PKIX validation to a specific CA)

    This code does not validate the certificate through PKIX
    certificate chains, for example,
    * no attempt is made to verify the integrity of the certificate chain
    * no checks on hostname in the certificate
    * no checks are made against any public CA
    * no checks on certificate expiration

References:

    The tlsa-survey tool (aka PryDane) is described in "Measuring DANE
    TLSA Deployment" by Liang Zhu, Duane Wessels, Allison Mankin, and
    John Heidemann, presented at the TMA 2015 workshop in Barcelona
    (http://tma-2015.cba.upc.edu/tma15-program)

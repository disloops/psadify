#!/usr/bin/env python

# MIT License
# Copyright (c) 2018 Matt Westfall (@disloops)

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__author__ = 'Matt Westfall'
__version__ = '1.0.1'
__email__ = 'disloops@gmail.com'

import os
import re
import sys
import time
import glob
import urllib
import socket
import argparse

# compile the latest attacks
def get_last_attacks():

    last_attacks = []

    # used to skip private IP ranges
    internal_ip_re = re.compile('^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*')

    # PSAD IP log files sorted by date
    files = sorted(glob.iglob('/var/log/psad/*/*_email_alert'), key=os.path.getmtime, reverse=True)

    # imperfect science of extracting info from WHOIS data
    country_re = re.compile('^country:', flags=re.IGNORECASE)

    # get the directories named after valid IPs only
    for file in files:
        if not os.path.isdir(file):
            try:
                file_dir = os.path.dirname(file)
                socket.inet_pton(socket.AF_INET, os.path.basename(file_dir))
                if not internal_ip_re.match(os.path.basename(file_dir)):

                    last_seen = time.ctime(os.path.getmtime(file))
                    first_seen = '?'
                    IP = '?'
                    country = '?'
                    ports = '?'

                    whois_file = file_dir + "/" + os.path.basename(file_dir) + "_whois"

                    with open(whois_file, 'r') as f:
                        for line in f:
                            if country == '?' and country_re.match(line):
                                country = line.split(None, 1)[1][:2]

                    with open(file, 'r') as f:

                        for line in f.readlines():
                            if first_seen == '?' and "overall scan start:" in line.lower():
                                first_seen = line.split(": ", 1)[1]
                            if IP == '?' and "source:" in line.lower():
                                IP = line.split(": ", 1)[1]
                            if ports == '?' and "scanned tcp ports" in line.lower():
                                ports = re.search('\[(.+?):', line).group(1)

                        attacker_dict = {
                            "last_seen": last_seen,
                            "first_seen": first_seen,
                            "IP": IP,
                            "country": country,
                            "ports": ports
                        }
                        last_attacks.append(attacker_dict)

            except:
                pass
            if len(last_attacks) == 20:
                break

    return last_attacks

# parse the top attackers file
def get_top_attackers():

    top_attackers = []
    raw_attackers = None

    # imperfect science of extracting info from WHOIS data
    country_re = re.compile('^country:', flags=re.IGNORECASE)
    host_re = re.compile('^(org-name|organi|owner:|netname)', flags=re.IGNORECASE)

    # used to skip private IP ranges
    internal_ip_re = re.compile('^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*')

    # using this while loop to get around instances where no data comes back
    # possibly due to the file being in use and locked
    while not raw_attackers:
        with open('/var/log/psad/top_attackers', 'r') as f:
            raw_attackers = f.readlines()

    for attacker in raw_attackers:
        if attacker[0].isdigit():

            try:
                IP = attacker.split()[0]
                hits = attacker.split()[2]
                country = '?'
                host = ['?']
                last_seen = '?'
                path = '/var/log/psad/' + IP
                whois_file = path + '/' + IP + '_whois'

                if not internal_ip_re.match(IP):
                    if os.path.isfile(whois_file):
                        with open(whois_file, 'r') as f:
                            for line in f:
                                if country == '?' and country_re.match(line):
                                    country = line.split(None, 1)[1][:2]
                                if ' ' in line and host_re.match(line):
                                    host.append(line.split(None, 1)[1])

                    for file in os.listdir(path):
                        if file.endswith('_email_alert'):
                            file_path = os.path.join(path, file)
                            last_seen = time.ctime(os.path.getmtime(file_path))

                    attacker_dict = {
                        "last_seen": last_seen,
                        "IP": IP,
                        "hits": hits,
                        "country": country,
                        "host": max(host, key=len)
                    }
                    top_attackers.append(attacker_dict)
            except:
                pass

    return top_attackers

# parse the top signatures file
def get_top_signatures():

    top_signatures = []

    with open('/var/log/psad/top_sigs', 'r') as f:
        raw_signatures = f.readlines()

    for signature in raw_signatures:
        if signature[0].isdigit():

            try:
                sid = signature.split()[0]
                sig = ' '.join(re.findall(r'"(.*?)"', signature))
                hits = ' '.join(signature.split('"')[-1:]).split()[0]

                sig_dict = {
                    "SID": sid,
                    "sig": sig,
                    "hits": hits
                }
                top_signatures.append(sig_dict)
            except:
                pass

    return top_signatures

# parse the top ports file
def get_top_ports():

    top_ports = []

    with open('/var/log/psad/top_ports', 'r') as f:
        raw_ports = f.readlines()

    for port in raw_ports:
        if port[0].isalpha():

            try:
                if port.split()[0] == 'tcp':
                    port_num = port.split()[1]
                    hits = port.split()[2]

                    port_dict = {
                        "port_num": port_num,
                        "hits": hits
                    }
                    top_ports.append(port_dict)
            except:
                pass

    return top_ports

# create last attacks HTML table
def get_last_attacks_html(last_attacks):

    last_attacks_html = '<table class="psadTable" id="lastAttacksTable">'
    last_attacks_html += '<tr class="psadTableRow">'
    last_attacks_html += '<td class="psadTableHead">Last Seen</td>'
    last_attacks_html += '<td class="psadTableHead">First Seen</td>'
    last_attacks_html += '<td class="psadTableHead">IP Address</td>'
    last_attacks_html += '<td class="psadTableHead">Country</td>'
    last_attacks_html += '<td class="psadTableHead">Ports Targeted</td>'
    last_attacks_html += '</tr>'

    for attack in last_attacks:

        IP_link = '<a href="https://www.whois.com/whois/' + attack['IP'] + '" target="_blank">'
        IP_link += attack['IP'] + '</a>'

        last_attacks_html += '<tr class="psadTableRow">'
        last_attacks_html += '<td class="psadTableCell">' + attack['last_seen'] + '</td>'
        last_attacks_html += '<td class="psadTableCell">' + attack['first_seen'] + '</td>'
        last_attacks_html += '<td class="psadTableCell">' + IP_link + '</td>'
        last_attacks_html += '<td class="psadTableCell">' + attack['country'] + '</td>'
        last_attacks_html += '<td class="psadTableCell">' + attack['ports'] + '</td>'
        last_attacks_html += '</tr>'

    last_attacks_html += '</table>'
    return last_attacks_html

# create top attackers HTML table
def get_attackers_html(top_attackers):

    top_attackers = sorted(top_attackers, key=lambda x: int(x['hits']), reverse=True)
    rows = 50 if len(top_attackers) > 50 else len(top_attackers)

    top_attackers_html = '<table class="psadTable" id="attackerTable">'
    top_attackers_html += '<tr class="psadTableRow">'
    top_attackers_html += '<td class="psadTableHead">Last Seen</td>'
    top_attackers_html += '<td class="psadTableHead">Hits</td>'
    top_attackers_html += '<td class="psadTableHead">IP Address</td>'
    top_attackers_html += '<td class="psadTableHead">Country</td>'
    top_attackers_html += '<td class="psadTableHead">Hosting Provider</td>'
    top_attackers_html += '</tr>'

    for attacker in top_attackers[:rows]:

        IP_link = '<a href="https://www.whois.com/whois/' + attacker['IP'] + '" target="_blank">'
        IP_link += attacker['IP'] + '</a>'

        top_attackers_html += '<tr class="psadTableRow">'
        top_attackers_html += '<td class="psadTableCell">' + attacker['last_seen'] + '</td>'
        top_attackers_html += '<td class="psadTableCell">' + attacker['hits'] + '</td>'
        top_attackers_html += '<td class="psadTableCell">' + IP_link + '</td>'
        top_attackers_html += '<td class="psadTableCell">' + attacker['country'].upper() + '</td>'
        top_attackers_html += '<td class="psadTableCellLeft">' + attacker['host'] + '</td>'
        top_attackers_html += '</tr>'

    top_attackers_html += '</table>'
    return top_attackers_html

def get_signatures_html(top_signatures):

    top_signatures_html = '<table class="psadTable" id="signatureTable">'
    top_signatures_html += '<tr class="psadTableRow">'
    top_signatures_html += '<td class="psadTableHead">Hits</td>'
    top_signatures_html += '<td class="psadTableHead">SID</td>'
    top_signatures_html += '<td class="psadTableHead">Signature</td>'
    top_signatures_html += '</tr>'

    for signature in top_signatures:

        sig_link = '<a href="https://www.google.com/search?q=' + urllib.quote_plus(signature['sig'])
        sig_link += '" target="_blank">' + signature['sig'] + '</a>'

        top_signatures_html += '<tr class="psadTableRow">'
        top_signatures_html += '<td class="psadTableCell">' + signature['hits'] + '</td>'
        top_signatures_html += '<td class="psadTableCell">' + signature['SID'] + '</td>'
        top_signatures_html += '<td class="psadTableCellLeft">' + sig_link + '</td>'
        top_signatures_html += '</tr>'

    top_signatures_html += '</table>'
    return top_signatures_html

def get_ports_html(top_ports):

    rows = 50 if len(top_ports) > 50 else len(top_ports)

    top_ports_html = '<div id="portTableDiv">'
    top_ports_html += '<table class="psadTable" id="portTable01">'
    top_ports_html += '<tr class="psadTableRow">'
    top_ports_html += '<td class="psadTableHead">Port</td>'
    top_ports_html += '<td class="psadTableHead">Hits</td>'
    top_ports_html += '</tr>'

    for port in top_ports[:rows//2]:

        port_link = '<a href="https://www.speedguide.net/port.php?port=' + port['port_num']
        port_link += '" target="_blank">' + port['port_num'] + '</a>'

        top_ports_html += '<tr class="psadTableRow">'
        top_ports_html += '<td class="psadTableCell">' + port_link + '</td>'
        top_ports_html += '<td class="psadTableCell">' + port['hits'] + '</td>'
        top_ports_html += '</tr>'

    top_ports_html += '</table>'
    top_ports_html += '<table class="psadTable" id="portTable02">'
    top_ports_html += '<tr class="psadTableRow">'
    top_ports_html += '<td class="psadTableHead">Port</td>'
    top_ports_html += '<td class="psadTableHead">Hits</td>'
    top_ports_html += '</tr>'

    for port in top_ports[rows//2:rows]:

        port_link = '<a href="https://www.speedguide.net/port.php?port=' + port['port_num']
        port_link += '" target="_blank">' + port['port_num'] + '</a>'

        top_ports_html += '<tr class="psadTableRow">'
        top_ports_html += '<td class="psadTableCell">' + port_link + '</td>'
        top_ports_html += '<td class="psadTableCell">' + port['hits'] + '</td>'
        top_ports_html += '</tr>'

    top_ports_html += '</table>'
    top_ports_html += '</div>'

    return top_ports_html

def get_css():

    css = """

a:link, a:active, a:visited {
    color: #55FF33;
    text-decoration: none;
}
a:hover {
    font-weight: bold;
}
body {
    background-color: #000000;
    color: #CCCCCC;
    font-family: Helvetica, Arial, Sans-Serif;
    font-size: small;
}
#lastAttacksTable, #attackerTable, #signatureTable {
    margin: 0px auto 40px auto;
}
#portTable01, #portTable02 {
    margin: 0px 25px 40px 25px;
}
#portTableDiv {
    align-items: center;
    display: flex;
    justify-content: center;
}
.headerBlock{
    color: #DDDDDD;
    margin: 50px auto 40px auto;
    text-align: center;
    max-width: 85%;
}
.footerBlock{
    color: #DDDDDD;
    margin: 0px auto 50px auto;
    text-align: center;
    max-width: 85%;
}
.psadTable, .psadTableRow, .psadTableHead, .psadTableCell {
    border: 1px solid #666666;
}
.psadTable {
    border-collapse: collapse;
    display: none;
    max-width: 85%;
    text-align: center;
}
.psadTableHead {
    font-weight: bold;
}
.psadTableCell, .psadTableCellLeft, .psadTableHead {
    padding: 5px 15px;
}
.psadTableCellLeft {
    text-align: left;
}

"""
    return css

def get_javascript():

    js = """

function showLastAttacksTable() {
    document.getElementById("lastAttacksTable").style.display = "table";
    document.getElementById("attackerTable").style.display = "none";
    document.getElementById("signatureTable").style.display = "none";
    document.getElementById("portTable01").style.display = "none";
    document.getElementById("portTable02").style.display = "none";

    document.getElementById("lastAttacksButton").style.fontWeight = "bold";
    document.getElementById("showAttackersButton").style.fontWeight = "normal";
    document.getElementById("topSignaturesButton").style.fontWeight = "normal";
    document.getElementById("topPortsButton").style.fontWeight = "normal";
}
function showAttackerTable() {
    document.getElementById("lastAttacksTable").style.display = "none";
    document.getElementById("attackerTable").style.display = "table";
    document.getElementById("signatureTable").style.display = "none";
    document.getElementById("portTable01").style.display = "none";
    document.getElementById("portTable02").style.display = "none";

    document.getElementById("lastAttacksButton").style.fontWeight = "normal";
    document.getElementById("showAttackersButton").style.fontWeight = "bold";
    document.getElementById("topSignaturesButton").style.fontWeight = "normal";
    document.getElementById("topPortsButton").style.fontWeight = "normal";
}
function showSignatureTable() {
    document.getElementById("lastAttacksTable").style.display = "none";
    document.getElementById("attackerTable").style.display = "none";
    document.getElementById("signatureTable").style.display = "table";
    document.getElementById("portTable01").style.display = "none";
    document.getElementById("portTable02").style.display = "none";

    document.getElementById("lastAttacksButton").style.fontWeight = "normal";
    document.getElementById("showAttackersButton").style.fontWeight = "normal";
    document.getElementById("topSignaturesButton").style.fontWeight = "bold";
    document.getElementById("topPortsButton").style.fontWeight = "normal";
}
function showPortsTable() {
    document.getElementById("lastAttacksTable").style.display = "none";
    document.getElementById("attackerTable").style.display = "none";
    document.getElementById("signatureTable").style.display = "none";
    document.getElementById("portTable01").style.display = "table";
    document.getElementById("portTable02").style.display = "table";

    document.getElementById("lastAttacksButton").style.fontWeight = "normal";
    document.getElementById("showAttackersButton").style.fontWeight = "normal";
    document.getElementById("topSignaturesButton").style.fontWeight = "normal";
    document.getElementById("topPortsButton").style.fontWeight = "bold";
}
window.onload = function() {
    showLastAttacksTable();
};

"""
    return js

def get_html_header():

    conf_file = "/etc/psad/psad.conf"
    uptime = time.ctime(os.path.getmtime(conf_file))

    article_link = '<a href="https://disloops.com/psad-on-raspberry-pi" target="_blank">PSAD on Raspberry Pi</a>'

    html = '<div class="headerBlock">'
    html += '<span style="font-weight: bold;">PORT SCAN ATTACK DETECTOR (PSAD)</span>'
    html += '<br><br>'
    html += 'This page contains the output of the Port Scan Attack Detector (PSAD) daemon running on my home network.'
    html += '<br><br>'
    html += 'These statistics have been tracked since ' + uptime + '.&nbsp;&nbsp;'
    html += 'Read more here:&nbsp;&nbsp;' + article_link
    html += '<br><br>'
    html += '<span style="font-weight: bold;">Click here to show the various live data being tracked:</span>'
    html += '<br><br>'
    html += '<span id="lastAttacksButton" style="font-weight: bold;">'
    html += '<a onclick="showLastAttacksTable();" href="#">Last Attacks</a>'
    html += '</span>'
    html += '&nbsp;&nbsp;|&nbsp;&nbsp;'
    html += '<span id="showAttackersButton">'
    html += '<a onclick="showAttackerTable();" href="#">Top Attackers</a>'
    html += '</span>'
    html += '&nbsp;&nbsp;|&nbsp;&nbsp;'
    html += '<span id="topSignaturesButton">'
    html += '<a onclick="showSignatureTable();" href="#">Top Signatures</a>'
    html += '</span>'
    html += '&nbsp;&nbsp;|&nbsp;&nbsp;'
    html += '<span id="topPortsButton">'
    html += '<a onclick="showPortsTable();" href="#">Top Ports</a>'
    html += '</span>'
    html += '</div>'

    return html

def get_html_footer():

    github_link = '<a href="https://github.com/disloops/psadify" target="_blank">https://github.com/disloops/psadify</a>'

    html = '<div class="footerBlock">'
    html += 'The script to generate this HTML from PSAD output data can be downloaded here:&nbsp;&nbsp;'
    html += github_link
    html += '</div>'

    return html

def get_html(last_attacks, top_attackers, top_signatures, top_ports):

    html = '<!DOCTYPE html><html><head><meta charset="UTF-8">'
    html += '<meta http-equiv="refresh" content="120">'
    html += '<title>Port Scan Attack Detector (PSAD) Status</title>'
    html += '<style type="text/css">' + get_css() + '</style>'
    html += '<script>' + get_javascript() + '</script>'
    html += '</head><body>'
    html += get_html_header()
    html += get_last_attacks_html(last_attacks)
    html += get_attackers_html(top_attackers)
    html += get_signatures_html(top_signatures)
    html += get_ports_html(top_ports)
    html += get_html_footer()
    html += '</body></html>'

    return html

def main():

    logo_msg = '\n PSADify v' + __version__

    epilog_msg = ('example:\n' +
                 ' $ python psadify.py -output status.html\n' +
                 logo_msg + '\n A tool for converting PSAD output into HTML.')

    parser = argparse.ArgumentParser(add_help=False,formatter_class=argparse.RawTextHelpFormatter,epilog=epilog_msg)
    parser.add_argument('-h', '--help', dest='show_help', action='store_true', help='Show this message and exit\n\n')
    parser.add_argument('-o', '--output', help='The file that is generated with the HTML content\n', type=str)
    parser.set_defaults(show_help='False')
    args = parser.parse_args()

    if args.show_help is True:
        print('')
        print(parser.format_help())
        sys.exit(0)

    print(logo_msg)

    output_file = 'status.html'
    if args.output:
        output_file = args.output

    html = get_html(get_last_attacks(), get_top_attackers(), get_top_signatures(), get_top_ports())

    with open(output_file, 'w') as f:
        print(' [*] Writing output to ' + output_file)
        f.write(html)

    print('')

if __name__ == '__main__':
    sys.exit(main())

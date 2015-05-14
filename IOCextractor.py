#!/usr/bin/env python
# -*- coding: utf-8 -*-

#This script helps extract indicators of compromise (IOCs) from a text file.
#A user can add or remove tagged indicators then export the remaining tags.
#Usage: "python IOCextractor.py" or "python IOCextractor.py document.txt"
#2012 Stephen Brannon, Verizon RISK Team

import re
import sys


import cybox
from cybox import helper as cybox_helper
from cybox.core import Observables, Observable
from cybox.objects.uri_object import URI
import cybox.utils
import stix
from stix.core import STIXPackage, STIXHeader
from cybox.common import Hash
from cybox.objects.file_object import File

from ioc_writer import ioc_api, ioc_common

reMD5 = r"([A-F]|[0-9]){32}"
reSHA1 = r"([A-F]|[0-9]){40}"
reSHA256 = r"([A-F]|[0-9]){64}"
reIPv4 = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|\[\.\])){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
reURL = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)(/\S+)"
reDomain = r"[A-Z0-9\-\.\[\]]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"
reEmail = r"\b[A-Za-z0-9._%+-]+(@|\[@\])[A-Za-z0-9.-]+(\.|\[\.\])(XN--CLCHC0EA0B2G2A9GCD|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--11B5BS3A9AJ6G|XN--MGBERP4A5D4AR|XN--XKC2DL3A5EE0H|XN--80AKHBYKNJ4F|XN--XKC2AL3HYE2A|XN--LGBBAT1AD8J|XN--MGBC0A9AZCG|XN--9T4B11YI5A|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--YFRO4I67O|XN--YGBI2AMMX|XN--3E0B707E|XN--JXALPDLP|XN--KGBECHTV|XN--OGBPF8FL|XN--0ZWM56D|XN--45BRJ9C|XN--80AO21A|XN--DEBA0AD|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--J6W193G|XN--KPRW13D|XN--KPRY57D|XN--PGBS0DH|XN--S9BRJ9C|XN--90A3AC|XN--FIQS8S|XN--FIQZ9S|XN--O3CW4H|XN--WGBH1C|XN--WGBL6A|XN--ZCKZAH|XN--P1AI|MUSEUM|TRAVEL|AERO|ARPA|ASIA|COOP|INFO|JOBS|MOBI|NAME|BIZ|CAT|COM|EDU|GOV|INT|MIL|NET|ORG|PRO|TEL|XXX|AC|AD|AE|AF|AG|AI|AL|AM|AN|AO|AQ|AR|AS|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|CR|CU|CV|CW|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|IO|IQ|IR|IS|IT|JE|JM|JO|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MK|ML|MM|MN|MO|MP|MQ|MR|MS|MT|MU|MV|MW|MX|MY|MZ|NA|NC|NE|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SX|SY|SZ|TC|TD|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|ZA|ZM|ZW)\b"

def dotToNum(ip): return int(''.join(["%02x"%int(i) for i in ip.split('.')]),16)

def extract_iocs(text):
    iocs = {'md5' : [],
            'sha1' : [],
            'sha256' : [],
            'ipv4' : [],
            'url' : [],
            'domain' : [],
            'email' : []}

    #md5
    for m in re.finditer(reMD5, text, re.IGNORECASE):
        iocs['md5'].append(m.string[m.start():m.end()].upper())

    #sha1
    for m in re.finditer(reSHA1, text, re.IGNORECASE):
        iocs['sha1'].append(m.string[m.start():m.end()].upper())

    #sha256
    for m in re.finditer(reSHA256, text, re.IGNORECASE):
        iocs['sha256'].append(m.string[m.start():m.end()].upper())

    #ipv4
    for m in re.finditer(reIPv4, text, re.IGNORECASE):
        result = m.string[m.start():m.end()]
        result = result.replace('[','').replace(']','') #remove brackets
        #reject private, link-local, and loopback IPs
        if result.find('10.') != 0 and \
           result.find('192.168') != 0 and \
           result.find('127') != 0:
            if (dotToNum(result) < dotToNum('172.16.0.0') or \
                dotToNum(result) > dotToNum('172.31.255.255')) and \
               (dotToNum(result) < dotToNum('169.254.1.0') or \
                dotToNum(result) > dotToNum('169.254.254.255')):
                iocs['ipv4'].append(result)

    #url
    for m in re.finditer(reURL, text, re.IGNORECASE):
        result = m.string[m.start():m.end()]
        #drop trailing punctuation
        while (u'.,\u201d"\'\u2019').find(result[-1]) != -1:
            result = result[:-1]
        iocs['url'].append(result)

    #domain
    for m in re.finditer(reDomain, text, re.IGNORECASE):
        #reject if preceding character is @ or following character is /
        if text[min(m.start()-1, 0)] != '@':
            if text[min(len(m.string)-1, m.end()+1)] != '/':
                iocs['domain'].append(m.string[m.start():m.end()])

    #email
    for m in re.finditer(reEmail, text, re.IGNORECASE):
        iocs['email'].append(m.string[m.start():m.end()])

    # Remove duplicates
    for ioc_type, ioc_list in iocs.items():
        iocs[ioc_type] = list(set(ioc_list))
    return iocs


def export_csv(iocs):
    output = 'IOC,Type\n'
    for ioc_type, ioc_list in iocs.items():
        for ioc in ioc_list:
            output += '"' + ioc + '",' + ioc_type + '\n'
    return output

def export_stix(iocs):
    """
    Export the tagged items in STIX format.
    BROKE!
    """
    observables_doc = None

    stix_package = STIXPackage()
    stix_header = STIXHeader()
    stix_header.description = filename
    stix_package.stix_header = stix_header


    for ioc in iocs['md5']:
        observable = cybox_helper.create_file_hash_observable('', value)
        observables.append(observable)
        stix_package.add_observable(observable)
        indicators.append(value)

    if t == 'ipv4':
        if not value in indicators:
            observable = cybox_helper.create_ipv4_observable(value)
            observables.append(observable)
            stix_package.add_observable(observable)
            indicators.append(value)

    elif t == 'domain':
        if not value in indicators:
            observable = cybox_helper.create_domain_name_observable(value)
            observables.append(observable)
            stix_package.add_observable(observable)
            indicators.append(value)

    elif t == 'url':
        if not value in indicators:
            observable = cybox_helper.create_url_observable(value)
            observables.append(observable)
            stix_package.add_observable(observable)
            indicators.append(value)

    elif t == 'email':
        if not value in indicators:
            observable = cybox_helper.create_email_address_observable(value)
            observables.append(observable)
            stix_package.add_observable(observable)
            indicators.append(value)

    if len(observables) > 0:
        if not filename.endswith('.xml'):
            filename = "%s.xml" % filename #add .xml extension if missing
        # end if

        with open(filename, "wb") as f:
            stix_xml = stix_package.to_xml()
            f.write(stix_xml)

        # end if

def export_openioc():
    '''
    Export the tagged items in OpenIOC 1.1 format.
    This prompts the user to determine which directory they want the IOC saved
    out too.

    Email tags default to 'Email/From' address, implying that the email address
    found is the source address of an email.  This may not be accurate in all
    cases.
    BROKE!
    '''
    def make_network_uri(uri, condition='contains', negate=False, preserve_case = False):
        document = 'Network'
        search = 'Network/URI'
        content_type = 'string'
        content = uri
        IndicatorItem_node = ioc_api.make_IndicatorItem_node(condition, document, search, content_type, content, negate=negate, preserve_case=preserve_case, context_type = None)
        return IndicatorItem_node

    def make_email_from(from_address, condition='contains', negate=False, preserve_case = False):
        document = 'Email'
        search = 'Email/From'
        content_type = 'string'
        content = from_address
        IndicatorItem_node = ioc_api.make_IndicatorItem_node(condition, document, search, content_type, content, negate=negate, preserve_case=preserve_case, context_type = None)
        return IndicatorItem_node

    output_directory = askdirectory(title = "Save IOC To")

    if output_directory:
        indicator_nodes = []
        for tag in tags:
            temp_indicators = []
            myhighlights = text.tag_ranges(tag)
            mystart = 0
            for h in myhighlights:
                if mystart == 0:
                    mystart = h
                else:
                    mystop = h
                    # Deobfuscate ip addresses, domain names and email addresses
                    value = text.get(mystart,mystop).replace('[.]','.').replace('[@]','@')
                    if tag == 'md5':
                        value = value.upper()
                        if value not in temp_indicators:
                            indicator_node = ioc_common.make_fileitem_md5sum(value)
                            indicator_nodes.append(indicator_node)
                            temp_indicators.append(value)
                    elif tag == 'ipv4':
                        if value not in temp_indicators:
                            indicator_node = ioc_common.make_portitem_remoteip(value)
                            indicator_nodes.append(indicator_node)
                            temp_indicators.append(value)
                    elif tag == 'domain':
                        if value not in temp_indicators:
                            indicator_node = ioc_common.make_dnsentryitem_recordname(value)
                            indicator_nodes.append(indicator_node)
                            temp_indicators.append(value)
                    elif tag == 'url':
                        if value not in temp_indicators:
                            indicator_node = make_network_uri(value)
                            indicator_nodes.append(indicator_node)
                            temp_indicators.append(value)
                    elif tag == 'email':
                        if value not in temp_indicators:
                            indicator_node = make_email_from(value)
                            indicator_nodes.append(indicator_node)
                            temp_indicators.append(value)
                    else:
                        print 'Unknown tag encountered [%s]' % str(tag)
                    mystart = 0

    if len(indicator_nodes) > 0:
        ioc_obj = ioc_api.IOC(name = "IOC Extractor", description = "IOC generated with IOCExtractor")
        for indicator in indicator_nodes:
            ioc_obj.top_level_indicator.append(indicator)
        ioc_obj.write_ioc_to_file(output_directory)
    return True



test = '''
f4db7003155a381d1b4e1568fc852bc4
POODLES
123.123.123.123
123[.]123[.]123[.]123.123.123.123
extract_iocs(open('TestDocument.txt').read())
www.google.com
google.com
http://wwww.google.com
'''

if __name__ == '__main__':
    iocs = extract_iocs(test)
    print iocs
    print export_csv(iocs)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nmap
import datetime
import os

from nose.tools import assert_equals
from nose.tools import raises
from nose import with_setup

from multiprocessing import Value

"""
test_nmap.py - tests cases for python-nmap

Source code : https://bitbucket.org/xael/python-nmap

Author :

* Alexandre Norman - norman at xael.org

Contributors:

* Steve 'Ashcrow' Milner - steve at gnulinux.net
* Brian Bustin - brian at bustin.us
* old.schepperhand
* Johan Lundberg
* Thomas D. maaaaz
* Robert Bost
 
Licence : GPL v3 or any later version


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""

##########################################################################################

"""
This plugin provides ``--pdb`` and ``--pdb-failures`` options. The ``--pdb``
option will drop the test runner into pdb when it encounters an error. To
drop into pdb on failure, use ``--pdb-failures``.

这个插件提供``--pdb``和``--pdb-failures``选项。 
``--pdb``选项会在遇到错误时将测试运行器放到pdb中。
在失败时放入pdb，使用``--pdb-failures``。
"""

import pdb
from nose.plugins.base import Plugin

class Pdb(Plugin):
    """
    Provides --pdb and --pdb-failures options that cause the test runner to
    drop into pdb if it encounters an error or failure, respectively.
	提供--pdb和--pdb-failures选项，这些选项会导致测试运行器分别在遇到错误或故障时落入pdb。
    """
    enabled_for_errors = False
    enabled_for_failures = False
    score = 5 # run last, among builtins
    
    def options(self, parser, env):
        """Register commandline options.
		定义命令行选项：包括--pdb, --pdb-failures,  --pdb-errors
        """
        parser.add_option(
            "--pdb", action="store_true", dest="debugBoth",
            default=env.get('NOSE_PDB', False),
            help="Drop into debugger on failures or errors")
        parser.add_option(
            "--pdb-failures", action="store_true",
            dest="debugFailures",
            default=env.get('NOSE_PDB_FAILURES', False),
            help="Drop into debugger on failures")
        parser.add_option(
            "--pdb-errors", action="store_true",
            dest="debugErrors",
            default=env.get('NOSE_PDB_ERRORS', False),
            help="Drop into debugger on errors")

    def configure(self, options, conf):
        """Configure which kinds of exceptions trigger plugin.
		通过检查异常来匹配哪一个类型的异常触发插件
        """
        self.conf = conf
        self.enabled_for_errors = options.debugErrors or options.debugBoth
        self.enabled_for_failures = options.debugFailures or options.debugBoth
        self.enabled = self.enabled_for_failures or self.enabled_for_errors

    def addError(self, test, err):
        """Enter pdb if configured to debug errors.
		如果配置调试结果是调试错误把错误放入pdb
        """
        if not self.enabled_for_errors:
            return
        self.debug(err)

    def addFailure(self, test, err):
        """Enter pdb if configured to debug failures.
		 如果配置调试结果是调试失败把错误放入pdb
        """
        if not self.enabled_for_failures:mortem
            return
        self.debug(err)
	
	"""
	post_mortem的注释解释是
	sys.exc_info() returns (type, value, traceback) if an exception is being handled, otherwise it returns None
	
	"""
    def debug(self, err):
        import sys # FIXME why is this import here?
        ec, ev, tb = err
        stdout = sys.stdout
        sys.stdout = sys.__stdout__
        try:
            pdb.post_mortem(tb)
        finally:
            sys.stdout = stdout

##########################################################################################

#设置扫描模块进行扫描
def setup_module():
    global nm
    nm = nmap.PortScanner()


@raises(nmap.PortScannerError)
def test_wrong_args():
    nm.scan(arguments='-wrongargs')

#测试主机扫描错误
def test_host_scan_error():
    assert('error' in nm.scan('noserver.example.com', arguments='-sP')['nmap']['scaninfo'])

#测试是否能读取xml文件
def xmlfile_read_setup():
    nm.analyse_nmap_xml_scan(open('scanme_output.xml').read())

#测试输入命令行的命令是否合法
@with_setup(xmlfile_read_setup)
def test_command_line():
    try:
        global NMAP_XML_VERSION
        NMAP_XML_VERSION = os.environ['NMAP_XML_VERSION']
    except:
        raise ValueError('Set env NMAP_XML_VERSION')
    
    assert_equals(nm.command_line(), './nmap-{0}/nmap -sV -oX scanme_output-{0}.xml scanme.nmap.org'.format(NMAP_XML_VERSION))

#测试扫描信息是否存在
@with_setup(xmlfile_read_setup)
def test_scan_info():
    assert('tcp' in nm.scaninfo())
    assert('method' in nm.scaninfo()['tcp'])
    assert_equals('connect', nm.scaninfo()['tcp']['method'])
    assert('services' in nm.scaninfo()['tcp'])

#测试列表里是否有目标主机的存在
@with_setup(xmlfile_read_setup)
def test_all_hosts():
    assert_equals(['45.33.32.156'], nm.all_hosts())

#测试主机
@with_setup(xmlfile_read_setup)
def test_host():
    assert_equals('scanme.nmap.org', nm['45.33.32.156'].hostname())
    assert({'name':'scanme.nmap.org', 'type':'user'} in  nm['45.33.32.156'].hostnames())
    assert_equals('up', nm['45.33.32.156'].state())
    assert_equals(['tcp'], nm['45.33.32.156'].all_protocols())

#
def test_host_no_hostname():
    # Covers bug : https://bitbucket.org/xael/python-nmap/issues/7/error-with-hostname
    nm.scan('127.0.0.2')
    assert_equals('', nm['127.0.0.2'].hostname())

    
@with_setup(xmlfile_read_setup)
def test_port():
    assert_equals([80, 9929, 22, 31337], list(nm['45.33.32.156']['tcp'].keys()))
    assert(nm['45.33.32.156'].has_tcp(22))
    assert(nm['45.33.32.156'].has_tcp(23) == False)
    assert('conf' in list(nm['45.33.32.156']['tcp'][22]))
    assert('cpe' in list(nm['45.33.32.156']['tcp'][22]))
    assert('name' in list(nm['45.33.32.156']['tcp'][22]))
    assert('product' in list(nm['45.33.32.156']['tcp'][22]))
    assert('reason' in list(nm['45.33.32.156']['tcp'][22]))
    assert('state' in list(nm['45.33.32.156']['tcp'][22]))
    assert('version' in list(nm['45.33.32.156']['tcp'][22]))
                  
    assert('10' in nm['45.33.32.156']['tcp'][22]['conf'])
    global NMAP_XML_VERSION
    if NMAP_XML_VERSION=='6.40':
        assert_equals('', nm['45.33.32.156']['tcp'][22]['cpe'])
        assert_equals('', nm['45.33.32.156']['tcp'][22]['product'])
        assert_equals('', nm['45.33.32.156']['tcp'][22]['version'])
    else:
        assert('cpe:/o:linux:linux_kernel' in nm['45.33.32.156']['tcp'][22]['cpe'])
        assert('OpenSSH' in nm['45.33.32.156']['tcp'][22]['product'])
        assert('6.6.1p1 Ubuntu 2ubuntu2.3' in nm['45.33.32.156']['tcp'][22]['version'])
        
    assert('ssh' in nm['45.33.32.156']['tcp'][22]['name'])
    assert('syn-ack' in nm['45.33.32.156']['tcp'][22]['reason'])
    assert('open' in nm['45.33.32.156']['tcp'][22]['state'])

    assert_equals(nm['45.33.32.156']['tcp'][22], nm['45.33.32.156'].tcp(22))

#测试列表扫描主机的结果
@with_setup(xmlfile_read_setup)
def test_listscan():
    assert_equals('1', nm.scanstats()['uphosts'])
    assert_equals('0', nm.scanstats()['downhosts'])
    assert_equals('1', nm.scanstats()['totalhosts'])
    assert('timestr' in nm.scanstats().keys())
    assert('elapsed' in nm.scanstats().keys())

#测试输出格式是否为CSV    
@with_setup(xmlfile_read_setup)
def test_csv_output():
    assert_equals('host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe',
                  nm.csv().split('\n')[0].strip())

    global NMAP_XML_VERSION
    if NMAP_XML_VERSION == '6.40':
        assert_equals('45.33.32.156;scanme.nmap.org;user;tcp;22;ssh;open;;protocol 2.0;syn-ack;;10;',
                      nm.csv().split('\n')[1].strip())
    else:
        assert_equals('45.33.32.156;scanme.nmap.org;user;tcp;22;ssh;open;OpenSSH;"Ubuntu Linux; protocol 2.0";syn-ack;6.6.1p1 Ubuntu 2ubuntu2.3;10;cpe:/o:linux:linux_kernel',
                      nm.csv().split('\n')[1].strip())

#测试列表扫描 
def test_listscan():
    assert(0 < len(nm.listscan('192.168.1.0/30')))
    assert_equals(['127.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3'], 
                  nm.listscan('localhost/30'))


#测试对IPV6的扫描
def test_ipv6():
    if os.getuid() == 0:
        r = nm.scan('127.0.0.1', arguments='-6')
    else:
        r = nm.scan('127.0.0.1', arguments='-6', sudo=True)


#测试IPV4的异步扫描
def test_ipv4_async():
    global FLAG
    FLAG = Value('i', 0)
    nma = nmap.PortScannerAsync()

    def callback_result(host, scan_result):
        global FLAG
        FLAG.value = 1

    nma.scan(hosts='127.0.0.1',
             arguments='-p 22 -Pn',
             callback=callback_result)

    while nma.still_scanning():
        nma.wait(2)

    assert_equals(FLAG.value, 1)

#测试IPV6的异步扫描
def test_ipv6_async():
    global FLAG_ipv6
    FLAG_ipv6 = Value('i', 0)
    nma_ipv6 = nmap.PortScannerAsync()

    def callback_result(host, scan_result):
        global FLAG_ipv6
        FLAG_ipv6.value = 1

    nma_ipv6.scan(hosts='::1',
             arguments='-6 -p 22 -Pn',
             callback=callback_result)

    while nma_ipv6.still_scanning():
        nma_ipv6.wait(2)

    assert_equals(FLAG_ipv6.value, 1)

#扫描本地主机用户的信息
def scan_localhost_sudo_arg_O():
    lastnm = nm.get_nmap_last_output()

    if len(lastnm) > 0:
        try:
            nm.analyse_nmap_xml_scan(lastnm)
        except:
            pass
        else:
            if nm.command_line() == 'nmap -oX - -O 127.0.0.1':
                return

    if os.getuid() == 0:
        nm.scan('127.0.0.1', arguments='-O')
    else :
        nm.scan('127.0.0.1', arguments='-O', sudo=True)

#测试是否获得主机的信息
@with_setup(scan_localhost_sudo_arg_O)
def test_sudo():
    assert('osmatch' in nm['127.0.0.1'])
    assert(len(nm['127.0.0.1']['osmatch'][0]['osclass']) > 0)
    assert_equals('Linux', nm['127.0.0.1']['osmatch'][0]['osclass'][0]['vendor'])


@with_setup(scan_localhost_sudo_arg_O)
def test_parsing_osmap_osclass_and_others():
    # nosetests -v -s nmap/test_nmap.py:test_parsing_osmap_osclass_and_others
    assert('osmatch' in nm['127.0.0.1'])
    assert_equals(nm['127.0.0.1']['osmatch'][0]['name'], 'Linux 3.7 - 3.15')

    assert('accuracy' in nm['127.0.0.1']['osmatch'][0])
    assert('line' in nm['127.0.0.1']['osmatch'][0])

    assert('osclass' in nm['127.0.0.1']['osmatch'][0])
    assert_equals(nm['127.0.0.1']['osmatch'][0]['osclass'][0]['vendor'], 'Linux')

    assert('type' in nm['127.0.0.1']['osmatch'][0]['osclass'][0])
    assert('osfamily' in nm['127.0.0.1']['osmatch'][0]['osclass'][0])
    assert('osgen' in nm['127.0.0.1']['osmatch'][0]['osclass'][0])
    assert('accuracy' in nm['127.0.0.1']['osmatch'][0]['osclass'][0])



#测试本地主机的信息
@with_setup(scan_localhost_sudo_arg_O)
def test_all_protocols():
    assert('addresses' not in nm['127.0.0.1'].all_protocols())
    assert('hostnames' not in nm['127.0.0.1'].all_protocols())
    assert('status' not in nm['127.0.0.1'].all_protocols())
    assert('vendor' not in nm['127.0.0.1'].all_protocols())
    assert('osclass' not in nm['127.0.0.1'].all_protocols())
    assert('osmatch' not in nm['127.0.0.1'].all_protocols())
    assert('uptime' not in nm['127.0.0.1'].all_protocols())
    assert('portused' not in nm['127.0.0.1'].all_protocols())
    assert('tcp' in nm['127.0.0.1'].all_protocols())

#读取osmatch_output.xml文件，设置osmatch的xml格式输出
def xmlfile_read_setup_multiple_osmatch():
    nm.analyse_nmap_xml_scan(open('osmatch_output.xml').read())

#检查主机的osmatch里是否存在一些信息
@with_setup(xmlfile_read_setup_multiple_osmatch)
def test_multipe_osmatch():
    assert('osmatch' in nm['127.0.0.1'])
    assert('portused' in nm['127.0.0.1'])

    for osm in nm['127.0.0.1']['osmatch']:
        assert('accuracy' in osm)
        assert('line' in osm)
        assert('name' in osm)
        assert('osclass' in osm)
        assert('accuracy' in osm['osclass'][0])
        assert('cpe' in osm['osclass'][0])
        assert('osfamily' in osm['osclass'][0])
        assert('osgen' in osm['osclass'][0])
        assert('type' in osm['osclass'][0])
        assert('vendor' in osm['osclass'][0])

#测试是否对nmap扫描结果进行了编码
@with_setup(xmlfile_read_setup)
def test_convert_nmap_output_to_encoding():
    a=nm.analyse_nmap_xml_scan(open('scanme_output.xml').read())
    out = nmap.convert_nmap_output_to_encoding(a, code="ascii")
    assert(out['scan']['45.33.32.156']['addresses']['ipv4'] == b'45.33.32.156')

# def test_host_and_port_as_unicode():
#     # nosetests -x -s nmap/test_nmap.py:test_port_as_unicode
#     # Covers bug : https://bitbucket.org/xael/python-nmap/issues/9/can-not-pass-ports-with-unicode-string-at
#     nma = nm.scan(hosts=u'127.0.0.1', ports=u'22')
#     assert_equals(nma['nmap']['scaninfo']['error'], '')


#测试warning的警告信息是否存在
def test_WARNING_case_sensitive():
    nm.scan('localhost', arguments= '-S 127.0.0.1')
    assert('warning'  in nm.scaninfo())
    assert('WARNING' in nm.scaninfo()['warning'][0])

#测试异步扫描的情况
def test_scan_progressive():
    nmp = nmap.PortScannerAsync()

    def callback(host, scan_data):
        assert(host is not None)
    
    nmp.scan(hosts='127.0.0.1', arguments='-sV', callback=callback)
    nmp.wait()
    

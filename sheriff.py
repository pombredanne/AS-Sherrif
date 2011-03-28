#!/usr/bin/env python2
#
# Package vulnerability automatic sheriff
#
# Copyright (c) 2011 Eduardo Lopes
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#

import sys, getopt
import archpkg, pkgtrans, pkgversion, pkgvulns

def usage():
    print """
Package vulnerability automatic sheriff

Usage: sheriff [-v pkg-vulnerabilities] [-t pkg-trans-table]
               [-w warn-file] [-i ignored-urls] [-u update the file prior to execution]
"""
    sys.exit(1)
    
def fetch(filename):
    import urllib
    try:
        sys.stderr.write('Fetching the file from NetBSD website: \t\t \t')
        infile = urllib.urlopen('http://ftp.netbsd.org/pub/NetBSD/packages/vulns/pkg-vulnerabilities')
        sys.stderr.write('DONE.\n')
        try:
            outfile = open(filename,  'w')
        except:
            outfile = open('pkg-vulnerabilities', 'w')
        outfile.writelines(infile.readlines())   
        
    except:
        sys.stderr.write('No access to remote file, check your internet connection and try again.\n')
        

    
def log(warn_file, msg):
    """ Log a msg to the warn_file. """
    f = open(warn_file, 'a')
    f.write(msg)
    f.close()

def warn_unmatched(warn_file):
    """ Returns a callback to log unmatched packages to warn_file. """
    def callback(tup):
        log(warn_file, 'No match for package in translation table:\n%s\n\n' % repr(tup))
    return callback
    
def load_list(filename):
    """ Loads a list of one string per line from filename. """
    f = open(filename)
    content = [x.strip() for x in f.readlines()]
    f.close()
    return content

def main(vuln_file, trans_file, warn_file, ignore_file):
    """ Sheriff """
    # Load the ignore list
    ignore_list = load_list(ignore_file)

    # Load the translation database
    trans = pkgtrans.Translator(trans_file)
    pkg_list = trans.pkgsrc_list

    # Loops through the vulnerabilities list
    for (pkgname, version_patterns, original_pkgdesc, vulntype, vulnurl) in \
        pkgvulns.vuln_pkg_matcher_iterator(vuln_file, pkg_list, warn_unmatched(warn_file)):

        # Skip vulnerabilities included in the ignore list
        if vulnurl in ignore_list:
            sys.stderr.write('IGNORING %s\n' % repr((original_pkgdesc, vulntype, vulnurl)))
            continue
        
        # Translate pkgsrc name to ArchLinux package name
        arch_pkgname = trans.translate_name(pkgname)

        # Retrieve ArchLinux package version
        try:
            arch_pkgver = archpkg.get_version(arch_pkgname)
        except:
            log(warn_file, 'Arch package not available anymore: %s.\n\n' % repr(arch_pkgname))
            continue

        # Translate the version to pkgsrc format using the database
        try:
            pkgver = trans.translate_version(pkgname, arch_pkgver)
        except:
            log(warn_file, 'Could not translate version to pkgsrc: %s %s\n\n' % (pkgname, arch_pkgver))
            continue

        sys.stderr.write('CHECKING %s\n' % repr((original_pkgdesc, arch_pkgname, arch_pkgver)))
        
        # Check if the version is potentially vulnerable
        if pkgversion.match(version_patterns, pkgver):
            # Choose a mark
            t = 'VULN'
            if pkgver == None:
                t = 'WARN'
            if vulntype == 'eol':
                t = 'EOL'
            
            # Write information to stdout
            sys.stdout.write('%s %s\n' % (t, repr((arch_pkgname, arch_pkgver, original_pkgdesc, vulntype, vulnurl))))
            sys.stdout.flush()

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except:
        pass
    
    vuln_file = 'pkg-vulnerabilities'
    trans_file = 'pkg-trans-table'
    warn_file = 'warn-file'
    ignore_file = 'ignored-urls'
    
    try: opts, args = getopt.getopt(sys.argv[1:], 'h:v:t:w:i:u')
    except: usage()
    for o, a in opts:
        if o == '-h':
            usage()
        elif o == '-v':
            vuln_file = a
        elif o == '-t':
            trans_file = a
        elif o == '-w':
            warn_file = a
        elif o == '-i':
            ignore_file = a
        elif o == '-u':
            fetch(vuln_file)
        
    
    main(vuln_file, trans_file, warn_file, ignore_file)

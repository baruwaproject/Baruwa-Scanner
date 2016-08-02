package

  # hide from PAUSE
  Test::Baruwa::Scanner;

use strict;
use warnings;
use File::Touch;
use File::NCopy;
use FindBin '$Bin';
use File::Path qw(make_path remove_tree);
use Exporter qw/import/;

our @EXPORT = qw/create_config make_test_dirs/;

my @paths = (
    "$Bin/data/var/run/baruwa/scanner",
    "$Bin/data/var/spool/baruwa/incoming",
    "$Bin/data/var/spool/baruwa/quarantine",
    "$Bin/data/var/spool/exim/input",
    "$Bin/data/var/spool/exim.in/input",
    "$Bin/data/var/lock/Baruwa",
    "$Bin/data/etc/mail/baruwa/dynamic/rules",
    "$Bin/data/etc/mail/baruwa/dynamic/signatures",
);
my @files = ("$Bin/data/var/lock/Baruwa/test-lock");
our @msgs = ('1bUUOQ-0000g4-C7', '1bUWpd-0003hx-0i');

my $header1 = <<'HEADER1';
1bUUOQ-0000g4-C7-H
exim 93 93
<andrew@kudusoft.home.topdog-software.com>
1470123938 0
-helo_name fuzzylumpkins.home.topdog-software.com
-host_address 192.168.1.52.62765
-host_name fuzzylumpkins.home.topdog-software.com
-interface_address 192.168.1.14.25
-active_hostname ms2.home.topdog-software.com
-received_protocol esmtps
-aclc _n 1
0
-aclc _l 3
250
-aclm _av_scanner 32
clamd:/var/run/clamav/clamd.sock
-aclm 0 2
no
-body_linecount 2
-max_received_linelength 56
-tls_cipher TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256
-tls_ourcert -----BEGIN CERTIFICATE-----\nMIIGRjCCBS6gAwIBAgISAyaEr1dYsVd/bDUKfZmQByDFMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNjA2MTgxNjAwMDBaFw0x\nNjA5MTYxNjAwMDBaMCoxKDAmBgNVBAMTH3NjYW5uZXIubGFiLnRvcGRvZy1zb2Z0\nd2FyZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu9Xl/A28t\n3TeU/NkVQtAlioDOtEPqkOdslKviiKS/saQItq1ojlX/ohb37v+aW/74EiW2IjYd\nQwXa2sI1XjwLCHJ3PGQVpxMGhvvFW5lLfsBEi4lqjQdaIt7G/ZN3oAMJf078Hs28\nVMjKPvMx1HxwFmxcdeTwpjBOXa4F4/HqLcRp8JrOcwBbZMgQQxfZagfpmQ4XKMsC\nrXAL16KT6x+T0cLDxtLo32mc75hQZ1UhutWRNFI7O151pgS+cdNR77Y/FiRcfQ8y\nqz4NNIMQEuSy8UPtlHgw+mHrpjnYmuHf8ogchJMb3ZvdsQUX+xFL5a/VVtuMTYmk\nFdx7V0Guz7Y1YUzVDU9tsz96G0V3y0UaIOgAPUabBvUnsyhQ40Js7nR+/BZ34uzx\nFBLp9BSA5zhc3shslUN7WrV+3v9462mYKTrdjH3qwyaeh9d8HNM39O2yJmkkJvv/\npwevbLvqIRN3vCCBmlFi8qsgwOG08Zm/yiDOzFg5BjZVXw6ADI7sMUqlvxZx5whM\nOHnr1ua/GNpHRwTeXkGuQtvFAjqPmQAXZeSQTNuUpNrclosgEvgpJchAKnkqBRFd\nXpKqGbKlp8UQYg0AQJiIipXc06ZHiIrZQ4g+3cbr7uQUrkuFxti4bo4fpXOj4P6M\nkXfPnoAGqx+dpv85ZEMkLpCjVr3/hxzoLQIDAQABo4ICRDCCAkAwDgYDVR0PAQH/\nBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E\nAjAAMB0GA1UdDgQWBBR7b9MfNDC6QGMCDOdpv7W0QVUskjAfBgNVHSMEGDAWgBSo\nSmpjBH3duubRObemRWXv86jsoTBwBggrBgEFBQcBAQRkMGIwLwYIKwYBBQUHMAGG\nI2h0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcvMC8GCCsGAQUFBzAC\nhiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQub3JnLzBOBgNVHREERzBF\ngiJwb3N0b2ZmaWNlLmxhYi50b3Bkb2ctc29mdHdhcmUuY29tgh9zY2FubmVyLmxh\nYi50b3Bkb2ctc29mdHdhcmUuY29tMIH+BgNVHSAEgfYwgfMwCAYGZ4EMAQIBMIHm\nBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5j\ncnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0aWZpY2F0ZSBtYXkg\nb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRpZXMgYW5kIG9ubHkg\naW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQb2xpY3kgZm91bmQg\nYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9yeS8wDQYJKoZIhvcN\nAQELBQADggEBAC3CFdwbBbVbGGh4Lga1yF8GDVkkjE7twQmJI0oWfjX87J4axJIG\neLK+DGdI0ZuknpwsxxA6CBIdibS6X9beEOYaOHza8WLz7GW2zX2u5RuOuBq6bpkd\nvxA8iBdWPY63DH4tYVceo8dqmCrlbHtEA99pesvUcH3Uy2IlvlVRjdSk9t0m9+em\nMWeF9gOwYxgdPys3QUayfBzK/x+lltJjxisibtUbou2AYDTIiMCxjrRTyiYYctNR\nTRdVKV0nOjjgvsscIkFBKP6iwmzyH6DgOTsfkzZkTqlOVU0rrBMlWXlqmd+3Be1Q\nIzRqELgGN2T7+j8cY9mgKyYhzZ3GrH7HIac=\n-----END CERTIFICATE-----\n
XX
1
andrew@home.topdog-software.com

342P Received: from fuzzylumpkins.home.topdog-software.com ([192.168.1.52])
    by postoffice.lab.topdog-software.com with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
    (Baruwa 2.0)
    (envelope-from <andrew@kudusoft.home.topdog-software.com>)
    id 1bUUOQ-0000g4-C7 ret-id none;
    for andrew@home.topdog-software.com; Tue, 02 Aug 2016 09:45:38 +0200
038  Date: Tue, 02 Aug 2016 09:45:39 +0200
036T To: andrew@home.topdog-software.com
047F From: andrew@kudusoft.home.topdog-software.com
046  Subject: test Tue, 02 Aug 2016 09:45:39 +0200
057  X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
049  X-Baruwa-Virus-Checks: bypassed smtp time checks
HEADER1

my $body1 = <<'BODY1';
1bUUOQ-0000g4-C7-D
This is a test mailing
BODY1

my $header2 = <<'HEADER2';
1bUWpd-0003hx-0i-H
exim 93 93
<andrew@kudusoft.home.topdog-software.com>
1470133313 0
-helo_name fuzzylumpkins.home.topdog-software.com
-host_address 192.168.1.52.64587
-host_name fuzzylumpkins.home.topdog-software.com
-interface_address 192.168.1.14.25
-active_hostname ms2.home.topdog-software.com
-received_protocol esmtps
-aclc _n 1
0
-aclc _l 3
250
-aclm _av_scanner 32
clamd:/var/run/clamav/clamd.sock
-aclm 0 2
no
-body_linecount 112
-max_received_linelength 76
-tls_cipher TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256
-tls_ourcert -----BEGIN CERTIFICATE-----\nMIIGRjCCBS6gAwIBAgISAyaEr1dYsVd/bDUKfZmQByDFMA0GCSqGSIb3DQEBCwUA\nMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD\nExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNjA2MTgxNjAwMDBaFw0x\nNjA5MTYxNjAwMDBaMCoxKDAmBgNVBAMTH3NjYW5uZXIubGFiLnRvcGRvZy1zb2Z0\nd2FyZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu9Xl/A28t\n3TeU/NkVQtAlioDOtEPqkOdslKviiKS/saQItq1ojlX/ohb37v+aW/74EiW2IjYd\nQwXa2sI1XjwLCHJ3PGQVpxMGhvvFW5lLfsBEi4lqjQdaIt7G/ZN3oAMJf078Hs28\nVMjKPvMx1HxwFmxcdeTwpjBOXa4F4/HqLcRp8JrOcwBbZMgQQxfZagfpmQ4XKMsC\nrXAL16KT6x+T0cLDxtLo32mc75hQZ1UhutWRNFI7O151pgS+cdNR77Y/FiRcfQ8y\nqz4NNIMQEuSy8UPtlHgw+mHrpjnYmuHf8ogchJMb3ZvdsQUX+xFL5a/VVtuMTYmk\nFdx7V0Guz7Y1YUzVDU9tsz96G0V3y0UaIOgAPUabBvUnsyhQ40Js7nR+/BZ34uzx\nFBLp9BSA5zhc3shslUN7WrV+3v9462mYKTrdjH3qwyaeh9d8HNM39O2yJmkkJvv/\npwevbLvqIRN3vCCBmlFi8qsgwOG08Zm/yiDOzFg5BjZVXw6ADI7sMUqlvxZx5whM\nOHnr1ua/GNpHRwTeXkGuQtvFAjqPmQAXZeSQTNuUpNrclosgEvgpJchAKnkqBRFd\nXpKqGbKlp8UQYg0AQJiIipXc06ZHiIrZQ4g+3cbr7uQUrkuFxti4bo4fpXOj4P6M\nkXfPnoAGqx+dpv85ZEMkLpCjVr3/hxzoLQIDAQABo4ICRDCCAkAwDgYDVR0PAQH/\nBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E\nAjAAMB0GA1UdDgQWBBR7b9MfNDC6QGMCDOdpv7W0QVUskjAfBgNVHSMEGDAWgBSo\nSmpjBH3duubRObemRWXv86jsoTBwBggrBgEFBQcBAQRkMGIwLwYIKwYBBQUHMAGG\nI2h0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcvMC8GCCsGAQUFBzAC\nhiNodHRwOi8vY2VydC5pbnQteDMubGV0c2VuY3J5cHQub3JnLzBOBgNVHREERzBF\ngiJwb3N0b2ZmaWNlLmxhYi50b3Bkb2ctc29mdHdhcmUuY29tgh9zY2FubmVyLmxh\nYi50b3Bkb2ctc29mdHdhcmUuY29tMIH+BgNVHSAEgfYwgfMwCAYGZ4EMAQIBMIHm\nBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5j\ncnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGbVGhpcyBDZXJ0aWZpY2F0ZSBtYXkg\nb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5aW5nIFBhcnRpZXMgYW5kIG9ubHkg\naW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0aWZpY2F0ZSBQb2xpY3kgZm91bmQg\nYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcvcmVwb3NpdG9yeS8wDQYJKoZIhvcN\nAQELBQADggEBAC3CFdwbBbVbGGh4Lga1yF8GDVkkjE7twQmJI0oWfjX87J4axJIG\neLK+DGdI0ZuknpwsxxA6CBIdibS6X9beEOYaOHza8WLz7GW2zX2u5RuOuBq6bpkd\nvxA8iBdWPY63DH4tYVceo8dqmCrlbHtEA99pesvUcH3Uy2IlvlVRjdSk9t0m9+em\nMWeF9gOwYxgdPys3QUayfBzK/x+lltJjxisibtUbou2AYDTIiMCxjrRTyiYYctNR\nTRdVKV0nOjjgvsscIkFBKP6iwmzyH6DgOTsfkzZkTqlOVU0rrBMlWXlqmd+3Be1Q\nIzRqELgGN2T7+j8cY9mgKyYhzZ3GrH7HIac=\n-----END CERTIFICATE-----\n
XX
1
andrew@home.topdog-software.com

342P Received: from fuzzylumpkins.home.topdog-software.com ([192.168.1.52])
    by postoffice.lab.topdog-software.com with esmtps (TLS1.2:ECDHE_RSA_AES_256_GCM_SHA384:256)
    (Baruwa 2.0)
    (envelope-from <andrew@kudusoft.home.topdog-software.com>)
    id 1bUWpd-0003hx-0i ret-id none;
    for andrew@home.topdog-software.com; Tue, 02 Aug 2016 12:21:53 +0200
038  Date: Tue, 02 Aug 2016 12:21:54 +0200
036T To: andrew@home.topdog-software.com
047F From: andrew@kudusoft.home.topdog-software.com
046  Subject: test Tue, 02 Aug 2016 12:21:54 +0200
057  X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
018  MIME-Version: 1.0
072  Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_70687"
049  X-Baruwa-Virus-Checks: bypassed smtp time checks
HEADER2

my $body2 = <<'BODY2';
1bUWpd-0003hx-0i-D
------=_MIME_BOUNDARY_000_70687
Content-Type: text/plain

This is a test mailing
------=_MIME_BOUNDARY_000_70687
Content-Type: application/octet-stream; name="kudzu.doc"
Content-Description: kudzu.doc
Content-Disposition: attachment; filename="kudzu.doc"
Content-Transfer-Encoding: BASE64

RGV2aWNlcyBkZXRlY3RlZCBhcmUgb2YgdGhlIGZvbGxvd2luZyBjbGFzc2VzOgoKQ0xBU1NfVU5T
UEVDOiB1c2VkIGJ5IHRoZSBwcm9iZSB0byBzYXkgJ2xvb2sgZm9yIGV2ZXJ5dGhpbmcnCkNMQVNT
X05FVFdPUks6IG5ldHdvcmsgYWRhcHRlcnMKQ0xBU1NfU0NTSTogU0NTSSAoYW5kIHNvbWUgUkFJ
RCkgYWRhcHRlcnMKQ0xBU1NfTU9VU0U6IG1pY2UKQ0xBU1NfQVVESU86IHNvdW5kIGNhcmRzL2No
aXBzCkNMQVNTX0NEUk9NOiBDRC1ST01zLCBDRC1ScywgQ0QtUlcsIERWRC1ST01zLCBldGMuCkNM
QVNTX01PREVNOiBtb2RlbXM7IGFsc28sIFBDSSBzZXJpYWwgcG9ydHMgKEZJWE1FKQpDTEFTU19W
SURFTzogdmlkZW8gY2FyZHMKQ0xBU1NfVEFQRTogdGFwZSBkcml2ZXMKQ0xBU1NfRkxPUFBZOiBJ
REUsIFNDU0ksIGFuZCBVU0IgZmxvcHB5IGRyaXZlcy4gR2VuZXJpYyBQQyBmbG9wcHkgZHJpdmVz
CiAgICAgICAgICAgICAgYXJlICpub3QqIGRldGVjdGVkCkNMQVNTX1NDQU5ORVI6IHNjYW5uZXJz
CkNMQVNTX0hEOiBoYXJkIGRyaXZlcywgb3RoZXIgcmFuZG9tIHN0b3JhZ2UgbWVkaWEKQ0xBU1Nf
UkFJRDogUkFJRCBhZGFwdGVycy4gTm90IHJlYWxseSB1c2VkIGJ5IGFueXRoaW5nIGN1cnJlbnRs
eS4KQ0xBU1NfUFJJTlRFUjogcHJpbnRlcnMKQ0xBU1NfQ0FQVFVSRTogdmlkZW8gY2FwdHVyZSBi
b2FyZHMgKHRoaW5rIGJ0dHYpCkNMQVNTX0tFWUJPQVJEOiBrZXlib2FyZHMgKG9ubHkgcmV0dXJu
ZWQgb24gU3BhcmMgaGFyZHdhcmUpCkNMQVNTX01PTklUT1I6IEREQyBtb25pdG9ycwpDTEFTU19V
U0I6IFVTQiBjb250cm9sbGVycwpDTEFTU19TT0NLRVQ6IENhcmRidXMgY29udHJvbGxlcnMuIE1p
Z2h0IGJlIGV4cGFuZGVkIHRvIFBDTUNJQSBjb250cm9sbGVycwoJICAgICAgaW4gdGhlIGZ1dHVy
ZQpDTEFTU19PVEhFUjogYW55dGhpbmcgZWxzZQoKVGhlICdidXMnZXMgdGhhdCBpdCBmaW5kcyB0
aGluZ3Mgb24gYXJlIHRoZSBmb2xsb3dpbmc6CgpCVVNfUENJIC0gYWxzbyBzZWVzIGFueSBjdXJy
ZW50bHkgY29uZmlndXJlZCBDYXJkYnVzIHN0dWZmCkJVU19TQlVTIC0gdGhpcyBpcyBjdXJyZW50
bHkgYSBtaXNub21lci4gSXQgYXBwbGllcyB0byBhbnl0aGluZyBwdWxsZWQgZnJvbQoJdGhlIE9w
ZW5QUk9NIHByb2JlIG9uIFNwYXJjCkJVU19TRVJJQUwKQlVTX1BTQVVYIC0gdGhlIFBTLzIgbW91
c2UgY29udHJvbGxlcgpCVVNfUEFSQUxMRUwKQlVTX1NDU0kgLSB0aGlzIGluY2x1ZGVzIGlkZS1z
Y3NpIGFuZCBVU0Igc3RvcmFnZSwgaWYgY29uZmlndXJlZApCVVNfSURFCkJVU19LRVlCT0FSRCAt
IHRoaXMgaXMgd2hlcmUgaXQgbG9va3MgZm9yIFNwYXJjIGtleWJvYXJkIGluZm9ybWF0aW9uCkJV
U19EREMgLSBtb25pdG9ycwpCVVNfVVNCCkJVU19JU0FQTlAKQlVTX09USEVSIC0gYSBwbGFjZWhv
bGRlciwgbW9zdGx5CkJVU19VTlNQRUMgLSBhZ2FpbiwgdXNlZCBieSB0aGUgcHJvYmUgdG8gZmlu
ZCBhbnl0aGluZwoKRmllbGRzIHdyaXR0ZW4gaW4gL2V0Yy9zeXNjb25maWcvaHdjb25mIHRoYXQg
YXJlIGNvbW1vbiB0byBhbGwgZGV2aWNlcwoobm90ZTogc29tZSBtYXkgYmUgTlVMTDsgaWYgc28s
IHRoZXkgYXJlIG5vdCB3cml0dGVuKToKCmNsYXNzOgoJVGhlIGRldmljZSBjbGFzcwpidXM6CglU
aGUgJ2J1cycgdGhlIGRldmljZSB3YXMgcHJvYmVkIG9uCmRldGFjaGVkOgoJVGhpcyBpcyBmb3Ig
ZGV2aWNlcyB0aGF0IHRoZSB1c2VyIHdhbnRzIHRvIGxlYXZlIGFzIGNvbmZpZ3VyZWQsCglldmVu
IHRob3VnaCB0aGV5IG1heSBub3QgYmUgcHJvYmVkLiBDYXJkYnVzIGNhcmRzLCBpZiBkZXRlY3Rl
ZCwKCWFyZSBhdXRvbWF0aWNhbGx5IG1hcmtlZCBhcyB0aGlzOyBhIHVzZXIgbWF5IHdhbnQgdG8g
bWFyayB0aGlzCgl0aGVtc2VsdmVzIGZvciBzb21lIFVTQiBkZXZpY2VzLgpkcml2ZXI6CgkoYWx3
YXlzIG5vbi1OVUxMKQoJVGhlIGRyaXZlciB0byB1c2UgZm9yIHRoZSBjYXJkOyBpdCBtZWFucyBk
aWZmZXJlbnQgdGhpbmdzIGZvcgoJZGlmZmVyZW50IGRldmljZSBjbGFzc2VzLiBGb3IgbWljZSwg
aXQncyBhIG1vdXNlY29uZmlnIHR5cGU7Cglmb3IgdmlkZW8gY2FyZHMsIGl0J3MgYSBtYXBwaW5n
IGluIHRoZSBYY29uZmlndXJhdG9yICdDYXJkcycKCWRhdGFiYXNlOyBmb3IgKm1vc3QqIG90aGVy
IHRoaW5ncywgaXQncyBhIGtlcm5lbCBtb2R1bGUuCglUaGVyZSBhcmUgdGhyZWUgc3BlY2lhbCB2
YWx1ZXM6CgkgIC0gdW5rbm93bgoJICAgIFRoaXMgbWVhbnMgdGhhdCB3ZSBkb24ndCBrbm93IHdo
YXQgZHJpdmVyIHRvIHVzZQoJICAtIGlnbm9yZQoJICAgIFRoaXMgbWVhbnMgdGhhdCB3ZSBkb24n
dCBjYXJlIHdoYXQgZHJpdmVyIHRvIHVzZS4gR2VuZXJhbGx5CgkgICAgYXNzaWduZWQgdG8gUENJ
IGJyaWRnZXMgYW5kIHRoZSBsaWtlLiBJbiB0aGUgY3VycmVudAoJICAgIGltcGxlbWVudGF0aW9u
LCB0aGVyZSByZWFsbHkgaXMgbm8gZGlmZmVyZW5jZSBiZXR3ZWVuCgkgICAgJ2lnbm9yZScgYW5k
ICd1bmtub3duJy4KCSAgLSBkaXNhYmxlZAoJICAgIFRoaXMgbWVhbnMgdGhhdCB3ZSdkIG5vcm1h
bGx5IGFzc2lnbiBhIGRyaXZlciwgYnV0IHRoZQoJICAgIGRldmljZSBhcHBlYXJzIHRvIGJlIGRp
c2FibGVkIGluIHRoZSBCSU9TOyB0aGlzIGlzIG1haW5seQoJICAgIHNldCBmb3IgUENJIGRldmlj
ZXMuIFRoaXMgY2FuIG9jY3VyIGlmLCBmb3IgZXhhbXBsZSwKCSAgICB0aGUgdXNlciBzZXRzICdQ
blAgT1M6IFllcycgaW4gdGhlaXIgQklPUyBhbmQgbm8gaW50ZXJydXB0cwoJICAgIGFyZSBhc3Np
Z25lZCB0byBhbnkgY2FyZHMuCmRlc2M6CgkoYWx3YXlzIG5vbi1OVUxMKQoJU29tZSBnZW5lcmlj
IGRlc2NyaXB0aW9uIG9mIHRoZSBkZXZpY2UKZGV2aWNlOgoJRm9yIG5ldHdvcmsgY2FyZHMsIHRo
aXMgaXMgJ2V0aCcgdG8gaW5kaWNhdGUgZXRoZXJuZXQsIGFuZAoJJ3RyJyB0byBpbmRpY2F0ZSB0
b2tlbiByaW5nLiBGb3Igb3RoZXIgZGV2aWNlcywgaXQgaXMgdXN1YWxseQoJdGhlIGRldmljZSBu
b2RlIGFzc29jaWF0ZWQgd2l0aCBhIGRldmljZS4gRm9yIGV4YW1wbGUsIGZvciBhbgoJSURFIGRl
dmljZSwgaXQgd291bGQgYmUgYWxvbmcgdGhlIGxpbmVzIG9mICdoZGEnLiBGb3IgYSBzZXJpYWwK
CWRldmljZSwgaXQgY291bGQgYmUgJ3R0eVMxJy4KCQpEZXZpY2VzIGhhdmUgYWRkaXRpb25hbCBm
aWVsZHMgZGVwZW5kaW5nIG9uIHRoZSAnYnVzJyB0aGF0IHRoZXkgYXJlCmFzc29jaWF0ZWQgd2l0
aCAoYWdhaW4sIHNvbWUgbWF5IGJlIE5VTEwpOgoKQlVTX0REQwppZDoKCUEgRERDIFBuUCBpZCBm
cm9tIHRoZSBYY29uZmlndXJhdG9yIE1vbml0b3JzREIKaG9yaXpTeW5jTWluOgpob3JpelN5bmNN
YXg6CnZlcnRSZWZyZXNoTWluOgp2ZXJ0UmVmcmVzaE1heDoKCVRoZSBtaW5pbXVtIGFuZCBtYXhp
bXVtIGhvcml6b250YWwgc3luYyBhbmQgdmVydGljYWwgcmVmcmVzaAoJcmF0ZXMuCm1vZGVzOgoJ
QSBsaXN0IG9mIFZFU0EgY29tcGF0aWJsZSByZXNvbHV0aW9ucyBzdXBwb3J0ZWQgYnkgdGhlCgl2
aWRlbyBjYXJkL21vbml0b3IgY29tYm8uCm1lbToKCVRoZSBhbW91bnQgb2YgbWVtb3J5IGRldGVj
dGVkIG9uIHRoZSBhdHRhY2hlZCB2aWRlbyBjYXJkLgoJWWVzLCB0aGlzIGlzIHRlY2huaWNhbGx5
IGluIHRoZSB3cm9uZyBwbGFjZS4KCkJVU19JREUKcGh5c2ljYWw6CmxvZ2ljYWw6CglUaGUgcGh5
c2ljYWwgYW5kIGxvZ2ljYWwgZ2VvbWV0cnkgZm9yIHRoZSBkcml2ZSwgYXMgZ2xlYW5lZAoJZnJv
bSAvcHJvYy9pZGUuIE5vdCB1c2VkIGJ5IGFueXRoaW5nLgoKQlVTX0lTQVBOUApkZXZpY2VJZDoK
CVRoZSBJU0FQblAgbG9naWNhbCBkZXZpY2UgaWQKcGRldmljZUlkOgoJVGhlIHBhcmVudCBjYXJk
IElTQVBuUCBpZApjb21wYXQ6CglBbnkgY29tcGF0aWJpbGl0eSBQblAgaWQsIGlmIGF2YWlsYWJs
ZQpuYXRpdmU6CgknMScgaWYgYSBrZXJuZWwgZHJpdmVyIHdpdGggbmF0aXZlIElTQVBuUCBzdXBw
b3J0IGV4aXN0cwoJZm9yIHRoaXMgZGV2aWNlLiBHbGVhbmVkIGZyb20gL2xpYi9tb2R1bGVzL2B1
bmFtZSAtcmAvbW9kdWxlcy5pc2FwbnBtYXAKYWN0aXZlOgoJJzEnIGlmIHRoZSBkZXZpY2UgaXMg
Y3VycmVudGx5IGFjdGl2YXRlZApjYXJkbnVtOgoJVGhlIGluZGV4IG9mIHRoZSBjYXJkIHRoYXQg
dGhpcyBsb2dpY2FsIGRldmljZSBpcyBwYXJ0IG9mLgpsb2dkZXY6CglUaGUgbG9naWNhbCBkZXZp
Y2UgbnVtYmVyIGZvciB0aGlzIGxvZ2ljYWwgZGV2aWNlLgppbzoKaXJxOgpkbWE6Cm1lbToKCVJl
c291cmNlcyBjdXJyZW50bHkgaW4gdXNlIGJ5IHRoaXMgY2FyZC4KCkJVU19LRVlCT0FSRDoKQlVT
X1BTQVVYOgoobm9uZSkKCkJVU19QQVJBTExFTDoKcG5wbW9kZWw6CnBucG1mcjoKcG5wZGVzYzoK
CVRoZSBQblAgbW9kZWwgbmFtZSwgbWFudWZhdHVyZXIsIGFuZCBkZXNjcmlwdGlvbiBvZiB0aGlz
IGRldmljZS4KcG5wbW9kZXM6CglUaGUgUG5QIHN1cHBvcnRlZCAnbW9kZXMnIGZvciB0aGlzIGRl
dmljZS4KcGluZm86CglYIGFuZCBZIHJlc29sdXRpb24gb2YgdGhlIHByaW50ZXIsIHdoZXRoZXIg
b3Igbm90IGl0IHN1cHBvcnRzCgljb2xvciBhbmQgcmF3IEFTQ0lJIG91dHB1dCwgYW5kIGlmIGl0
IHVzZXMgYSB1bmlwcmludCBkcml2ZXIuCihOb3RlOiBpbmZvcm1hdGlvbiByZXR1cm5lZCBieSB0
aGUgcGFyYWxsZWwgcHJvYmUgaXMgbm90IGN1cnJlbnRseSB1c2VkCiBieSBrdWR6dSkKIApCVVNf
UENJOgp2ZW5kb3JJZDoKZGV2aWNlSWQ6CglUaGUgUENJIHZlbmRvciBhbmQgZGV2aWNlIGlkcy4K
c3ViVmVuZG9ySWQ6CnN1YkRldmljZUlkOgoJVGhlIFBDSSBzdWJ2ZW5kb3IgYW5kIHN1YmRldmlj
ZSBpZHMuCnBjaVR5cGU6CgknMScgZm9yIGEgbm9ybWFsIFBDSSBkZXZpY2UuICcyJyBmb3IgYSBD
YXJkYnVzIGRldmljZS4KCgpCVVNfU0JVUzoKd2lkdGg6CmhlaWdodDoKZnJlcToKbW9uaXRvcjoK
CVVzZWQgZm9yIG1vbml0b3JzIGRldGVjdGVkIHZpYSBPcGVuUFJPTTsgaXQgc3BlY2lmaWVzCgl0
aGUgcmVzb2x1dGlvbiBhbmQgZnJlcXVlbmN5LgoKQlVTX1NDU0k6Cmhvc3Q6CmNoYW5uZWw6Cmlk
OgpsdW46CglUaGUgaG9zdCwgY2hhbm5lbCwgaWQsIGFuZCBsdW4gb2YgdGhlIGRldmljZS4KCkJV
U19TRVJJQUw6CnBucG1mcjoKcG5wbW9kZWw6CnBucGNvbXBhdDoKcG5wZGVzYzoKCVRoZSBzZXJp
YWwgUG5QIG1hbnVmYWN0dXJlciwgbW9kZWwsIGNvbXBhdGliaWxpdHkgc3RyaW5nLAoJYW5kIGRl
c2NyaXB0aW9uIG9mIHRoZSBkZXZpY2UuCgpCVVNfVVNCOgp1c2JjbGFzczoKdXNic3ViY2xhc3M6
CnVzYnByb3RvY29sOgoJVGhlIFVTQiBjbGFzcywgc3ViY2xhc3MsIGFuZCBwcm90b2NvbC4gVXNl
ZCB0byBpZGVudGlmeQoJdGhlIGRldmljZSB0eXBlLgp1c2JidXM6CnVzYmxldmVsOgp1c2Jwb3J0
Ogpwcm9kdWN0cmV2aXNpb246CglPdGhlciBVU0IgZGF0YS4gTm90IGN1cnJlbnRseSB1c2VkLgp2
ZW5kb3JJZDoKZGV2aWNlSWQ6CglUaGUgdmVuZG9yIGFuZCBkZXZpY2UgSURzIG9mIHRoZSBVU0Ig
ZGV2aWNlLgoK

------=_MIME_BOUNDARY_000_70687--
BODY2

sub create_config {
    my ($from, $to, $path) = @_;
    open(FROM, '<', $from) or die "Could not open $from\n";
    open(TO,   '>', $to)   or die "Could not open $to\n";
    while (<FROM>) {
        unless (/PATH/) {
            print TO;
            next;
        }
        s/PATH/$path/;
        print TO;
    }
    close(FROM);
    close(TO);
}

sub make_test_dirs {
    remove_tree("$Bin/data/var/spool/baruwa/incoming", {keep_root => 1});
    foreach (@paths) {
        make_path($_, {mode => 0700}) unless (-d $_);
    }
    touch(@files) unless -f $files[0];
    unless (-f "$Bin/data/etc/mail/baruwa/virus.scanners.conf") {
        my $cp = File::NCopy->new(recursive => 1);
        $cp->copy("$Bin/../etc/mail/baruwa/*", "$Bin/data/etc/mail/baruwa/");
    }
    create_file("$Bin/data/var/spool/exim.in/input/1bUUOQ-0000g4-C7-H",
        $header1);
    create_file("$Bin/data/var/spool/exim.in/input/1bUUOQ-0000g4-C7-D", $body1);
    create_file("$Bin/data/var/spool/exim.in/input/1bUWpd-0003hx-0i-H",
        $header2);
    create_file("$Bin/data/var/spool/exim.in/input/1bUWpd-0003hx-0i-D", $body2);
}

sub create_file {
    my ($filename, $data) = @_;
    unless (-f "$filename") {
        open(FILE, '>', $filename) or die "Could not create file: $filename";
        print FILE $data;
        close(FILE);
    }
}

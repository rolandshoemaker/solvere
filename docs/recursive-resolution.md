# Internal recursive resolution algorithm

`solvere` uses the following algorithm internally to recursively resolve a DNS question and verify the responses

```
Relevant variables:
  AUTHORITY: Authoritative DNS server to send queries to
  QTYPE:     Type of DNS question to resolve records for
  QNAME:     Name of host to resolve records for

1. Set AUTHORITY randomly to one of the valid nameserver addresses for '.'
2. Set QTYPE to initial question type
3. Set question QTYPE to QTYPE
4. Send question to AUTHORITY
5. Check for out of bailiwick records for AUTHORITY in returned response
6. a. If ParentDS is set look for a DNSKEY for AUTHORITY and verify they match
   b. Check returned records are signed (RRSIG)
7. a. If returned RCODE is NXDOMAIN (3) and AUTHORITY has a DNSKEY check for signed denial
   b. If returned RCODE is not NOERROR (0) return SERVFAIL
8. If returned RCODE is NOERROR
  a. If returned records contain a CNAME record for the QNAME set QNAME to the CNAME target and
     restart at step 4
  b. Return records with NOERROR
9. a. If returned response is NODATA and AUTHORITY has a DNSKEY check for signed denial
   b. Return NODATA
10. a. If response is a REFERRAL and DS records are present set ParentDS
    b. If AUTHORITY has a DNSKEY check delegation is signed
    c. Choose a random nameserver from delegation response
    d. If nameserver doesn't have a relevant A/AAAA record use this process to lookup the address
    e. Set AUTHORITY to the address of the random nameserver and restart process at step 4
11. Return SERVFAIL
```

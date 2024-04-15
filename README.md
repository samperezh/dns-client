# DNS Client
Implementing a domain name system (DNS) client using sockets in Python.

The DnsClient application should be invoked at the command line using the following syntax: 

``` python3 dnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name ```

where the arguments are defined as follows:
- timeout (optional) gives how long to wait, in seconds, before retransmitting an unanswered query. Default value: 5.
- max-retries(optional) is the maximum number of times to retransmit an unanswered query before giving up. Default value: 3.
- port (optional) is the UDP port number of the DNS server. Default value: 53.
- -mx or -ns flags (optional) indicate whether to send a MX (mail server) or NS (name server) query. At most one of these can be given, and if neither is given then the client should send a
type A (IP address) query.
- server (required) is the IPv4 address of the DNS server, in a.b.c.d. format
- name (required) is the domain name to query for.

The following command should work when connected to McGill wifi: 
``` python3 dnsClient.py -t 10 -r 2 -mx @132.206.85.18 mcgill.ca ```

Example of result for the above command: 

DNSClient sending request for  mcgill.ca </br>
Server:  @132.206.85.18 </br>
Request type:  MX </br>
Response received after 0.4470961093902588 seconds (0 retries) </br>
***Answer Section (1 records)*** </br>
MX       mcgill-ca.mail.protection.outlook.com.          10      3600    nonauth </br>
***Additional Section (2 records)*** </br>
IP       104.47.75       10      nonauth </br>
IP       104.47.75       10      nonauth </br>

And the following command should work when not connected to McGill wifi: 
``` python3 dnsClient.py -t 10 -r 2 -mx @8.8.8.8 mcgill.ca ```


Python Version used: Python 3.11.1

Libraries used: 
- argparse (for parsing command line arguments)
- socket (low level networking interface)
- time 
- random

Note that this code was written and tested on macOS 13.2.1 (M1 chip) through Visual Studio Code terminal. 

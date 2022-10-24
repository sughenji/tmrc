# NMAP methodology

Start with `-T4` and tune some parameters:

`--max-retries` is 6 by default (with -T4 timing template), we can go with 1 or 2

`--max-rtt-timeout` check first with `ping` or `nping` and set it accordingly

`--host-timeout` you should limit the maximum time that nmap will spend on a single host, possibly with no services at all. Set to 5 o 10 minutes

rif.

https://www.youtube.com/watch?v=okCNbKSdmDA

Remember to save output with `-oA`.

Later on you can use this tool to generate spreadsheet documents:

https://github.com/NetsecExplained/Nmap-XML-to-CSV

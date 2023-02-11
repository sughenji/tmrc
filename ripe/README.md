# RIPE

Look for every object mantained by X:

```
whois -h whois.ripe.net -i mnt-by ITALIACOM-MNT
```

N.B. `--` is used to avoid sequent options to be considered as `whois` options instead of RIPE syntax

```
root@vm:~# whois "-Tperson FP12372-RIPE"
Usage: whois [OPTION]... OBJECT...

-h HOST, --host HOST   connect to server HOST
-p PORT, --port PORT   connect to PORT
-H                     hide legal disclaimers
      --verbose        explain what is being done
      --help           display this help and exit
      --version        output version information and exit
..
..
```

With `--`

```
root@vm:~# whois -- "-Tperson FP12372-RIPE"
% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

% Note: this output has been filtered.
%       To receive output for a database update, use the "-B" flag.

% Information related to 'FP12372-RIPE'

person:         Francesco Politi
address:        Micso S.r.l.
address:        Via Tiburtina Valeria, 318
address:        65128 - Pescara (PE)
phone:          +39 085 7996598
nic-hdl:        FP12372-RIPE
mnt-by:         QUIPO-MNT
mnt-by:         MICSO-MNT
created:        2017-01-17T20:25:03Z
last-modified:  2017-01-17T20:29:52Z
source:         RIPE # Filtered
```

Search for every network that belongs to some AS:

```
# whois -h whois.ripe.net -- "-i origin AS1111 -Troute" |grep route | awk '{ print $2 }'
```

## Useful online resources

https://irrexplorer.nlnog.net/





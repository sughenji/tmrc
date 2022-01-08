# Attacking Wordpress

- [Footprinting](#footprinting)
- [WPScan](#wpscan)

## Footprinting

Look for meta generator tag in HTML source:

```
<meta name="generator" content="WordPress 5.3.3" />
```

or:

```
# curl -s -X GET  http://10.10.11.125 | grep '<meta name="generator"'
<meta name="generator" content="WordPress 5.8.1" />
```


## WPScan

First, update:

```
# wpscan --update
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.
```

Then, enumerate with our API key:

```
# wpscan --url http://10.10.11.125 --enumerate --api-token vYvrH7HT2y...
```



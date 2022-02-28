# Hardening Wordpress

- [Web Application Firewall](#waf)
- [Stay updated](#update)
- [PHP version](#php)
- [Disable indexing](#index)
- [Disable XMLRPC](#xmlrpc)
- [Protect wp-login.php](#wp-login)
- [Rename admin user](#admin)
- [Rename backed url](#backend)
- [Do not store config, backup](#files)
- [WP-CLI](#wpcli)
- [Clamscan](#clamscan)
- [Check with grep](#grep)

## WAF

Eg. Wordfence, Sucuri

## update

Core, themes, plugins...

## PHP

https://www.php.net/supported-versions.php

## index

```
Options -Indexes
```

## XMLRPC

disable xmlrpc (with .htaccess)

```
<Files xmlrpc.php>
        Order Deny,Allow
        Deny from all
</Files>
```

## wp-login

```
<Files wp-login.php>
        order Deny,Allow
        Deny from all
        Allow from 1.2.3.0/255.255.255.0
</Files>
```

## admin

rename 'admin' user to something else (even better: remove user '1' (see mte90 backdoor))

## backend 

rename login url to something else

## files

avoid using common filename (eg. wp-config-bak.php, wp-config.txt...) they ARE checked by attackers	

## wpcli

Installing:

```
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
```

Check that `wp-cli.phar` is working:

```
php wp-cli.phar --info
```

or:

```
/opt/cpanel/ea-php73/root/usr/bin/php wp-cli.phar --info
```

Move into bin folder:

```
mv wp-cli.phar /usr/local/bin/wp

chmod +x /usr/local/bin/wp
```

Check actual Wordpress content:

```
wp core verify-checksums  --allow-root --path=/home/user/www/wordpresspath/ 
```

## Clamscan

## grep

Check with grep for suspicious strings

```
egrep -Rn "(passthru|exec|eval|shell_exec|assert|str_rot13|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile)" *.php
```




# Hardening Wordpress

- use some WAF (wordfence)
- always upgrade core, themes, plugins
- use LATEST php version
- disable indexing

```
Options -Indexes
```

- disable xmlrpc (with .htaccess)

```
<Files xmlrpc.php>
        Order Deny,Allow
        Deny from all
</Files>
```

- protect wp-login.php

```
<Files wp-login.php>
        order Deny,Allow
        Deny from all
        Allow from 1.2.3.0/255.255.255.0
</Files>
```

- rename 'admin' user to something else (even better: remove user '1' (see mte90 backdoor))

- rename login url to something else

- avoid using common filename (eg. wp-config-bak.php, wp-config.txt...) they ARE checked by attackers	

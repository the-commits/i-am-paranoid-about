Apache (.htaccess):

```Apache
<Files xmlrpc.php>
    Require all denied
</Files>
```
For old apache 2.2 and older
use Order Allow,Deny och Deny from all

```Apache
<Files xmlrpc.php>
    Require all denied
</Files>
```
For older Apache 2.2 use 
Order Allow,Deny and Deny from all


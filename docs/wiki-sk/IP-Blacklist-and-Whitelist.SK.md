# IP blacklist a whitelist

Whitelisting znamená, že všetky prístupy sú blokované okrem tých, ktoré sú explicitne povolené na komunikáciu s TinyFileManagerom.
Blacklisting znamená, že väčšina prístupov je povolená, ale vybrané entity sú blokované (napr. podozrivé adresy).

```php
// Possible rules are 'OFF', 'AND' or 'OR'
// OFF => Don't check connection IP, defaults to OFF
// AND => Connection must be on the whitelist, and not on the blacklist
// OR => Connection must be on the whitelist, or not on the blacklist
$ip_ruleset = 'OFF';

// Should users be notified of their block?
$ip_silent = true;

// IP-addresses, both ipv4 and ipv6
$ip_whitelist = array(
    '127.0.0.1',    // local ipv4
    '::1'           // local ipv6
);

// IP-addresses, both ipv4 and ipv6
$ip_blacklist = array(
    '0.0.0.0',      // non-routable meta ipv4
    '::'            // non-routable meta ipv6
);
```

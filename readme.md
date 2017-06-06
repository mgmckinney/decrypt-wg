AES Key wrap code from - https://gist.github.com/kurtbrose/4243633
Watchguard Key info from https://serverfault.com/questions/790339/merge-vpns-of-two-watchguard-firewalls-into-one-firewall

This code takes a watchguard PSK from the exported XML config file and returns plaintext value.
PSKs starting with '+' character are able to be decrypted.

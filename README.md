InstallCert
===========

This small program  which makes a connection to a HTTPS server and allows you to see all certificates that it returns + you can save any of them. I've added one small modification to this app - you can connect throgh Proxy to the service you're trying to reach. Sometimes it becomes handy. Options that are available : 

1. If you want simply to reach any website and download it's certificate then you can run java InstallCert host=[address of your host]

2. You can also specify port (port=[port number]) if it's not standard

3. In case when you have non-default password on your keystore, you need to add passphrase=[your keystore password]

4. If you would like to conncet via Proxy, then you need to add 2 more parameters : proxyHost=[proxyAddress] proxyPort=[proxyPortNumber]

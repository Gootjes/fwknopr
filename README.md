# fwknopr

R library implementing a tiny fwknop client for securely opening ports through Single Packet Authorization

## Usage

``` r
# This call opens tcp port 22 on the server for 30 seconds (server configurable)
# for the IP of the machine making the call.
# Leave out function arguments to use a credential manager for sensitive information.
fwknop(request_access = "tcp/22",
       server_ip = "<server ip>",
       server_port = 61102,
       server_key = "< Base 64 string >",
       server_hmac = "< Base 64 string >")
```

This gives enough time to connect through the server's firewall and start a ssh session.

``` bash
ssh user@server-ip
```

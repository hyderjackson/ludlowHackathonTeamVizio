# Vizio
## Differences between the ACR on and off tests:
When ACR was on, connections to 3.95.164.21 were established nearly every time
    <li>3.95.164.21 is an AWS server in West Virginia</li>
    <li>These connections always utilize UDP</li>


# Supersonic
## Suspicious IP Addresses
<li> 43.157.127.133 </li>
This address is registered under the name ACEVILLEPTELTD-SG. After a quick google search, it was revealed that Aceville Pte Ltd. is a Singaporean company with close connections to Tencent. There were connections to the address every 10-30 seconds, after which a string of four packets were sent back and forth (TCP, TLS 1.2, TCP, TLS 1.2)

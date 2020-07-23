# BinaryEdge Cheatsheet - [app.binaryedge.io](https://app.binaryedge.io)

Inspired by [Nate (@n0x08)](https://twitter.com/n0x08) cheatsheet, here is a version for BinaryEdge

- [Queries - Hosts tab](#queries---hosts-tab)
  * [Basics](#basics)
  * [Firewalls, VPNs, and other services](#firewalls--vpns--and-other-services)
  * [Databases and caches](#databases-and-caches)
  * [Web searches](#web-searches)
  * [SSL Searches](#ssl-searches)
  * [Misc](#misc)
- [Queries - Images tab](#queries---images-tab)

# Queries - Hosts tab

## Basics
**Port open** - Binaryedge uses modules, that means for example for RDP with

``` port:3389 ``` 

![⏩](https://app.binaryedge.io/services/query?query=port:3389&page=1)

you will get type:rdp + type:service-simple + type:ssl because its the 3 modules we use on the world wide scans

**Product**

```product:"OpenSSH" ```

**Search inside a banner**

```type:service-simple banner:"LANCOM Systems"```

**Product version minor AND bigger than (between X and Y)**

``` product:"nginx" version:>1.10.3 version:<1.14.0 ```

**Product version minor AND bigger than (between X and Y) and on specific ASN**

``` product:"nginx" version:>1.10.3 version:<1.14.0 asn:"16509" ```

**Product version minor AND bigger than (between X and Y) and on specific country**

``` product:"nginx" version:>1.10.3 version:<1.14.0 country:"US"```

**Looking for ICS / SCADA in specific country**

``` tag:ics country:"US" ```

## Firewalls, VPNs, and other services

**Citrix**

``` web.title:"Citrix" ```

``` web.title:"Netscaler" ```

``` web.title:"Endpoint Management - Console - Logon" ```

``` "Citrix-TransactionId" ```


**Pulse VPN**

``` product:"Pulse Secure VPN gateway http config" ```

**Palo Alto**

``` product:"Palo Alto GlobalProtect Gateway httpd" ```

**Juniper**

``` web.title:"Juniper"```

**Cyberoam SSL VPN:**

``` type:ssl cyberoam ```


**Cisco**

``` product:"Cisco" ```

``` web.title:"cisco" ```


**F5**

``` web.title:"BIG-IP®- Redirect" ```

``` web.favicon.mmh3:1996866236 ```

``` web.body.content:"BIG-IP logout"```

``` product:"BigIP" ```

``` type:service-simple BIGipServerPool ```

``` web.body.content:"LastMRH_Session" ```

``` web.body.content:"MRHSession" ```

**Gradle Server**

``` web.body.content:"Gradle Enterprise Server" ```

``` web.body.content:"Gradle Enterprise" ```

``` web.body.content:"Gradle" ```

**RDP Gateway**

``` web.body.content:"tdDomainUserNameLabel" ```

``` web.path:"/RDWeb/" ```

``` TSWAFeatureCheckCookie ```

**Oracle E-Business Suite**

``` web.title:"E-Business Suite Home Page Redirect" ```

``` web.path:"/OA_HTML/" ```

**Polycom Phones**

``` type:ssl polycom ```

**Webmin**

``` web.title:"Webmin" ```

**Team City**

``` web.title:"Log in to TeamCity" ```

``` "TeamCity-Node-Id" ```

**Barix Radio Encoder systems**

``` web.favicon.mmh3:2575496402 ``` 

**Sonos**

``` product:"Sonos" ```

**TP Link Gigagbit:**

``` TP-LINK Gigabit ```

``` product:"Router Webserver" ```

**TP Link:**

``` product:"TP-Link" ```

**Keenetic Smart Home:**

``` web.title:"Keenetic Web" ```

**Home Assistant Smart Home:**

``` web.title:"Home Assistant" ```

**Fritz!BOX SOHO Router:**

``` web.title:"FRITZ!Box" ```

**CoSHIP SOHO:**

``` web.title:"EMTA" ```

**Broadband Routers:**

``` web.body.content:"Broadband Router" ```

**MoviStar FIOS Router:**

``` web.title:"movistar" ```

**Blue Iris Video surveillance:**

``` web.title:"Blue Iris Login" ```

**Cambrium Networks:**

``` web.title:"ePMP" ```

**Vmware ESXI:**

``` product:"VMware ESXi"```

**Exposed Kubernetes k8s**

```type:kubernetes kubernetes.auth_required:false```

**Server Backup Manager:**

``` web.title:"Server Backup Manager" ```

**DrayTek Vigor router:**

``` web.title:"Vigor Login Page"```

**APC Power (UPS)**

``` web.title:"APC | Log On"```

**Metasploit**

``` web.title:"metasploit" ```

**HP iLO3**

``` type:ssl ssl.cert.issuer.common_name:ilo3 ```

**Zyxel**

```type:ssl ssl.cert.issuer.common_name:zyxel```

**ZTE**

``` web.title:"F660" ```

**SonicWall:**

``` web.title:"Policy Jump" ```

**Tilgin SOHO Router:**

``` web.title:myhome ```

**ActionTec**

``` web.title:"Advanced Setup - Security - Admin User Name" ```

**GPON**

``` web.title:"GPON" ```

**Mikrotik**

``` web.title:"RouterOS" ```

``` product:"mikrotik" ```

**Xiongmai NetSurveillance:**

``` web.title:"NETSurveillance WEB"```

**WatchGuard:**

```type:ssl ssl.cert.issuer.common_name:"Fireware web CA"```

**FosCAM IP Cameras:**

``` web.title:"IPCam Client" ```

**3CX VOIP:**

``` web.title:"3CX Phone System Management Console" ```


## Databases and caches
The < > signs work on anything that is an integer (for example when looking for versions, see Redis)

Verifying if the latest dataleak on the news was found via Binaryedge - replace leak by the word (maybe company name, tends to work well)

``` tag:database leak ```

**MongoDB - looking for non-empty mongoDB**

``` type:mongodb mongodb.totalSize:>1```

**MongoDB - searching for hacked mongoDB**

``` type:mongodb mongodb.names:hack```

``` type:mongodb mongodb.names:READ_ME_TO_RECOVER_YOUR_DATA```

**Redis - look for a version behind X**

``` type:redis redis.redis_version:<5.0.5 ```

**Elasticsearch - searching for hacked elastic**

``` type:elasticsearch elasticsearch.indices:contact_us_or_your_data_will_be_leaked```

**Elasticsearch - searching elastic with an indice named customer potentially leaking PII**

``` type:elasticsearch elasticsearch.indices:customer```

**Elasticsearch - only big ones**

``` type:elasticsearch elasticsearch.docs:>100000```

**Cassandra - Search for specific table names**

``` type:cassandra cassandra.table_names:user ```

**Cassandra - Search for specific keyspace name**

``` type:cassandra cassandra.keyspace_names:user ```

**RethinkDB - search on table names for users**

``` type:rethinkdb rethinkdb.table_names:users ```

**memcached exposed**

``` type:memcached ```

**MQTT brokers exposed to the internet with no auth and exposing topics**

``` type:mqtt mqtt.auth:false mqtt.num_topics:>0 ```

## Web searches

**Web - Searching for a specific header (this one is for a few pre programmed extracted headers full list here https://docs.binaryedge.io/search-web-headers/ if it doesnt work, go to option two)**

``` _exists_:web.headers.x_runtime ```

**Web - Searching for a specific header (option 2) or body content**

``` web.body.content:"Index of" ```

**Web - Searching for a specific HTTP title**

``` web.title:"Admin" ``` 

**Web - if you found something using the web searches above just use the favicon or body hashes to find how many exist**

``` web.favicon.mmh3:2294504639 ```

``` web.favicon.md5:5b6aae267f5115817162d44721d17b49 ```

``` web.body.sha256:c980258c50bc0b5137ddea75bc41eb3c0634153d3fbe05b0fd3aeab9673944da ```

## SSL Searches

**Find expired SSL Certificates**

``` ssl.cert.self_signed:true ```

**Look for a specific SSL cert using sha1 fingerprint**

``` ssl.cert.sha1_fingerprint:"e4:62:89:cc:d2:d7:08:ec:37:dc:1c:2e:a8:9b:7f:e5:5d:26:0d:c7" ```

**Look for a JA3 of the SSL cert**

``` ssl.server_info.ja3_digest:e35df3e00ca4ef31d42b34bebaa2f86e ```

## Misc

**RDP only with screenshot**

``` type:rdp has_screenshot:true ```

**Bluekeep** - machines vulnerable to bluekeep

``` type:bluekeep```

**FTP** look for the word games in content of open ftp with anonymous user

``` type:ftp ftp.user:anonymous ftp.names:"games" ```

**RSYNC** - look for the word Linux on the content of open rsync servers

``` type:rsync rsync.banner:linux```

# Queries - Images tab

Looking for RDNS

```rdns:verizon.com```

Looking for VNC in the United states

```tags:"vnc" country:US```

Looking for hacked machines - this uses our OCR system

```hacked```

Looking for RDP in a specific ASN

``` asn:"16276" tags:"rdp" ```


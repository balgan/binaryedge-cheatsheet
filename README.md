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

``` port:3389 ```  [⏩](https://app.binaryedge.io/services/query?query=port:3389&page=1)

you will get type:rdp + type:service-simple + type:ssl because its the 3 modules we use on the world wide scans

**Product**

```product:"OpenSSH" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22OpenSSH%22&page=1)

**Search inside a banner**

```type:service-simple banner:"LANCOM Systems"``` [⏩](https://app.binaryedge.io/services/query?query=type:service-simple%20banner:%22LANCOM%20Systems%22&page=1)

**Product version minor AND bigger than (between X and Y)**

``` product:"nginx" version:>1.10.3 version:<1.14.0 ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22nginx%22%20version:%3E1.10.3%20version:%3C1.14.0&page=1)

**Product version minor AND bigger than (between X and Y) and on specific ASN**

``` product:"nginx" version:>1.10.3 version:<1.14.0 asn:"16509" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22nginx%22%20version:%3E1.10.3%20version:%3C1.14.0%20asn:%2216509%22&page=1)

**Product version minor AND bigger than (between X and Y) and on specific country**

``` product:"nginx" version:>1.10.3 version:<1.14.0 country:"US"``` [⏩](https://app.binaryedge.io/services/query?query=product:%22nginx%22%20version:%3E1.10.3%20version:%3C1.14.0%20country:%22US%22&page=1)

**Looking for ICS / SCADA in specific country**

``` tag:ics country:"US" ``` [⏩](https://app.binaryedge.io/services/query?query=tag:ics%20country:%22US%22&page=1)

## Firewalls, VPNs, and other services

**Mobile Iron**

```web.favicon.md5:c3ee66d45636052a69bab53600f2f878```[⏩](https://app.binaryedge.io/services/query?query=web.favicon.md5:c3ee66d45636052a69bab53600f2f878)

```web.favicon.md5:8a185957a6b153314bab3668b57f18f4```[⏩](https://app.binaryedge.io/services/query?query=web.favicon.md5:8a185957a6b153314bab3668b57f18f4) 

```web.path.keyword: "/mifs/user/login.jsp"```[⏩](https://app.binaryedge.io/services/query?query=web.path.keyword:%20%22%2Fmifs%2Fuser%2Flogin.jsp%22) 


**Citrix**

``` web.title:"Citrix" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Citrix%22&page=1)

``` web.title:"Netscaler" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Netscaler%22&page=1)

``` web.title:"Endpoint Management - Console - Logon" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Endpoint%20Management%20-%20Console%20-%20Logon%22&page=1)

``` "Citrix-TransactionId" ``` [⏩](https://app.binaryedge.io/services/query?query=%22Citrix-TransactionId%22&page=1)


**Pulse VPN**

``` product:"Pulse Secure VPN gateway http config" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22Pulse%20Secure%20VPN%20gateway%20http%20config%22&page=1)

**Palo Alto**

``` product:"Palo Alto GlobalProtect Gateway httpd" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22Palo%20Alto%20GlobalProtect%20Gateway%20httpd%22&page=1)

**Juniper**

``` web.title:"Juniper"``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Juniper%22&page=1)

**Cyberoam SSL VPN:**

``` type:ssl cyberoam ``` [⏩](https://app.binaryedge.io/services/query?query=type:ssl%20cyberoam&page=1)


**Cisco**

``` product:"Cisco" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22Cisco%22&page=1)

``` web.title:"cisco" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22cisco%22&page=1)


**F5**

``` web.title:"BIG-IP®- Redirect" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22BIG-IP%C2%AE-%20Redirect%22&page=1)

``` web.favicon.mmh3:1996866236 ``` [⏩](https://app.binaryedge.io/services/query?query=web.favicon.mmh3:1996866236&page=1)

``` web.body.content:"BIG-IP logout"``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22BIG-IP%20logout%22&page=1)

``` product:"BigIP" ``` [⏩](https://app.binaryedge.io/services/query?query=port:3389&page=1)

``` type:service-simple BIGipServerPool ``` [⏩](https://app.binaryedge.io/services/query?query=type:service-simple%20BIGipServerPool&page=1)

``` web.body.content:"LastMRH_Session" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22LastMRH_Session%22&page=1)

``` web.body.content:"MRHSession" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22MRHSession%22&page=1)

**Gradle Server**

``` web.body.content:"Gradle Enterprise Server" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22Gradle%20Enterprise%20Server%22&page=1)

``` web.body.content:"Gradle Enterprise" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22Gradle%20Enterprise%22&page=1)

``` web.body.content:"Gradle" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22Gradle%22&page=1)

**RDP Gateway**

``` web.body.content:"tdDomainUserNameLabel" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22tdDomainUserNameLabel%22&page=1)

``` web.path:"/RDWeb/" ``` [⏩](https://app.binaryedge.io/services/query?query=web.path:%22%2FRDWeb%2F%22&page=1)

``` TSWAFeatureCheckCookie ``` [⏩](https://app.binaryedge.io/services/query?query=TSWAFeatureCheckCookie&page=1)

**Oracle E-Business Suite**

``` web.title:"E-Business Suite Home Page Redirect" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22E-Business%20Suite%20Home%20Page%20Redirect%22&page=1)

``` web.path:"/OA_HTML/" ``` [⏩](https://app.binaryedge.io/services/query?query=web.path:%22%2FOA_HTML%2F%22&page=1)

**Polycom Phones**

``` type:ssl polycom ``` [⏩](https://app.binaryedge.io/services/query?query=type:ssl%20polycom&page=1)

**Webmin**

``` web.title:"Webmin" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Webmin%22&page=1)

**Team City**

``` web.title:"Log in to TeamCity" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Log%20in%20to%20TeamCity%22&page=1)

``` "TeamCity-Node-Id" ``` [⏩](https://app.binaryedge.io/services/query?query=%22TeamCity-Node-Id%22&page=1)

**Barix Radio Encoder systems**

``` web.favicon.mmh3:2575496402 ``` [⏩](https://app.binaryedge.io/services/query?query=web.favicon.mmh3:2575496402&page=1)

**Sonos**

``` product:"Sonos" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22Sonos%22&page=1)

**TP Link Gigagbit:**

``` TP-LINK Gigabit ``` [⏩](https://app.binaryedge.io/services/query?query=TP-LINK%20Gigabit&page=1)

``` product:"Router Webserver" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22Router%20Webserver%22&page=1)

**TP Link:**

``` product:"TP-Link" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22TP-Link%22&page=1)

**Keenetic Smart Home:**

``` web.title:"Keenetic Web" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Keenetic%20Web%22&page=1)

**Home Assistant Smart Home:**

``` web.title:"Home Assistant" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Home%20Assistant%22&page=1)

**Fritz!BOX SOHO Router:**

``` web.title:"FRITZ!Box" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22FRITZ!Box%22&page=1)

**CoSHIP SOHO:**

``` web.title:"EMTA" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22EMTA%22&page=1)

**Broadband Routers:**

``` web.body.content:"Broadband Router" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22Broadband%20Router%22&page=1)

**MoviStar FIOS Router:**

``` web.title:"movistar" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22movistar%22&page=1)

**Blue Iris Video surveillance:**

``` web.title:"Blue Iris Login" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Blue%20Iris%20Login%22&page=1)

**Cambrium Networks:**

``` web.title:"ePMP" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22ePMP%22&page=1)

**Vmware ESXI:**

``` product:"VMware ESXi"``` [⏩](https://app.binaryedge.io/services/query?query=product:%22VMware%20ESXi%22&page=1)


**Exposed Kubernetes k8s**

```type:kubernetes kubernetes.auth_required:false``` [⏩](https://app.binaryedge.io/services/query?query=type:kubernetes%20kubernetes.auth_required:false&page=1)

**Server Backup Manager:**

``` web.title:"Server Backup Manager" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Server%20Backup%20Manager%22&page=1)

**DrayTek Vigor router:**

``` web.title:"Vigor Login Page"``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Vigor%20Login%20Page%22&page=1)

**APC Power (UPS)**

``` web.title:"APC | Log On"``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22APC%20%7C%20Log%20On%22&page=1)

**Metasploit**

``` web.title:"metasploit" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22metasploit%22&page=1)

**HP iLO3**

``` type:ssl ssl.cert.issuer.common_name:ilo3 ``` [⏩](https://app.binaryedge.io/services/query?query=type:ssl%20ssl.cert.issuer.common_name:ilo3&page=1)

**Zyxel**

```type:ssl ssl.cert.issuer.common_name:zyxel``` [⏩](https://app.binaryedge.io/services/query?query=type:ssl%20ssl.cert.issuer.common_name:zyxel&page=1)

**ZTE**

``` web.title:"F660" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22F660%22&page=1)

**SonicWall:**

``` web.title:"Policy Jump" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Policy%20Jump%22&page=1)

**Tilgin SOHO Router:**

``` web.title:myhome ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:myhome&page=1)

**ActionTec**

``` web.title:"Advanced Setup - Security - Admin User Name" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Advanced%20Setup%20-%20Security%20-%20Admin%20User%20Name%22&page=1)

**GPON**

``` web.title:"GPON" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22GPON%22&page=1)

**Mikrotik**

``` web.title:"RouterOS" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22RouterOS%22&page=1)

``` product:"mikrotik" ``` [⏩](https://app.binaryedge.io/services/query?query=product:%22mikrotik%22&page=1)

**Xiongmai NetSurveillance:**

``` web.title:"NETSurveillance WEB"``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22NETSurveillance%20WEB%22&page=1)

**WatchGuard:**

```type:ssl ssl.cert.issuer.common_name:"Fireware web CA"``` [⏩](https://app.binaryedge.io/services/query?query=type:ssl%20ssl.cert.issuer.common_name:%22Fireware%20web%20CA%22&page=1)

**FosCAM IP Cameras:**

``` web.title:"IPCam Client" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22IPCam%20Client%22&page=1)

**3CX VOIP:**

``` web.title:"3CX Phone System Management Console" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%223CX%20Phone%20System%20Management%20Console%22&page=1)


## Databases and caches
The < > signs work on anything that is an integer (for example when looking for versions, see Redis)

Verifying if the latest dataleak on the news was found via Binaryedge - replace leak by the word (maybe company name, tends to work well)

``` tag:database leak ``` [⏩](https://app.binaryedge.io/services/query?query=tag:database%20leak&page=1)

**MongoDB - looking for non-empty mongoDB**

``` type:mongodb mongodb.totalSize:>1``` [⏩](https://app.binaryedge.io/services/query?query=type:mongodb%20mongodb.totalSize:%3E1&page=1)

**MongoDB - searching for hacked mongoDB**

``` type:mongodb mongodb.names:hack``` [⏩](https://app.binaryedge.io/services/query?query=type:mongodb%20mongodb.names:hack&page=1)

``` type:mongodb mongodb.names:READ_ME_TO_RECOVER_YOUR_DATA``` [⏩](https://app.binaryedge.io/services/query?query=type:mongodb%20mongodb.names:READ_ME_TO_RECOVER_YOUR_DATA&page=1)

**Redis - look for a version behind X**

``` type:redis redis.redis_version:<5.0.5 ``` [⏩](https://app.binaryedge.io/services/query?query=type:redis%20redis.redis_version:%3C5.0.5&page=1)

**Elasticsearch - searching for hacked elastic**

``` type:elasticsearch elasticsearch.indices:contact_us_or_your_data_will_be_leaked``` [⏩](https://app.binaryedge.io/services/query?query=type:elasticsearch%20elasticsearch.indices:contact_us_or_your_data_will_be_leaked&page=1)

**Elasticsearch - searching elastic with an indice named customer potentially leaking PII**

``` type:elasticsearch elasticsearch.indices:customer``` [⏩](https://app.binaryedge.io/services/query?query=type:elasticsearch%20elasticsearch.indices:customer&page=1)

**Elasticsearch - only big ones**

``` type:elasticsearch elasticsearch.docs:>100000``` [⏩](https://app.binaryedge.io/services/query?query=type:elasticsearch%20elasticsearch.docs:%3E100000&page=1)

**Cassandra - Search for specific table names**

``` type:cassandra cassandra.table_names:user ``` [⏩](https://app.binaryedge.io/services/query?query=type:cassandra%20cassandra.table_names:user&page=1)

**Cassandra - Search for specific keyspace name**

``` type:cassandra cassandra.keyspace_names:user ``` [⏩](https://app.binaryedge.io/services/query?query=type:cassandra%20cassandra.keyspace_names:user&page=1)

**RethinkDB - search on table names for users**

``` type:rethinkdb rethinkdb.table_names:users ``` [⏩](https://app.binaryedge.io/services/query?query=type:rethinkdb%20rethinkdb.table_names:users&page=1)

**memcached exposed**

``` type:memcached ``` [⏩](https://app.binaryedge.io/services/query?query=type:memcached&page=1)

**MQTT brokers exposed to the internet with no auth and exposing topics**

``` type:mqtt mqtt.auth:false mqtt.num_topics:>0 ``` [⏩](https://app.binaryedge.io/services/query?query=type:mqtt%20mqtt.auth:false%20mqtt.num_topics:%3E0&page=1)

## Web searches

**Web - Searching for a specific header (this one is for a few pre programmed extracted headers full list here https://docs.binaryedge.io/search-web-headers/ if it doesnt work, go to option two)**

``` _exists_:web.headers.x_runtime ``` [⏩](https://app.binaryedge.io/services/query?query=_exists_:web.headers.x_runtime&page=1)

**Web - Searching for a specific header (option 2) or body content**

``` web.body.content:"Index of" ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.content:%22Index%20of%22&page=1)

**Web - Searching for a specific HTTP title**

``` web.title:"Admin" ``` [⏩](https://app.binaryedge.io/services/query?query=web.title:%22Admin%22&page=1)

**Web - if you found something using the web searches above just use the favicon or body hashes to find how many exist**

``` web.favicon.mmh3:2294504639 ``` [⏩](https://app.binaryedge.io/services/query?query=web.favicon.mmh3:2294504639&page=1)

``` web.favicon.md5:5b6aae267f5115817162d44721d17b49 ``` [⏩](https://app.binaryedge.io/services/query?query=web.favicon.md5:5b6aae267f5115817162d44721d17b49&page=1)

``` web.body.sha256:c980258c50bc0b5137ddea75bc41eb3c0634153d3fbe05b0fd3aeab9673944da ``` [⏩](https://app.binaryedge.io/services/query?query=web.body.sha256:c980258c50bc0b5137ddea75bc41eb3c0634153d3fbe05b0fd3aeab9673944da&page=1)

## SSL Searches

**Find expired SSL Certificates**

``` ssl.cert.self_signed:true ``` [⏩](https://app.binaryedge.io/services/query?query=ssl.cert.self_signed:true&page=1)

**Look for a specific SSL cert using sha1 fingerprint**

``` ssl.cert.sha1_fingerprint:"e4:62:89:cc:d2:d7:08:ec:37:dc:1c:2e:a8:9b:7f:e5:5d:26:0d:c7" ``` [⏩](https://app.binaryedge.io/services/query?query=ssl.cert.sha1_fingerprint:%22e4:62:89:cc:d2:d7:08:ec:37:dc:1c:2e:a8:9b:7f:e5:5d:26:0d:c7%22&page=1)


**Look for a JA3 of the SSL cert**

``` ssl.server_info.ja3_digest:e35df3e00ca4ef31d42b34bebaa2f86e ``` [⏩](https://app.binaryedge.io/services/query?query=ssl.server_info.ja3_digest:e35df3e00ca4ef31d42b34bebaa2f86e&page=1)


## Misc

**RDP only with screenshot**

``` type:rdp has_screenshot:true ``` [⏩](https://app.binaryedge.io/services/query?query=type:rdp%20has_screenshot:true&page=1)

**Bluekeep** - machines vulnerable to bluekeep

``` type:bluekeep``` [⏩](https://app.binaryedge.io/services/query?query=type:bluekeep&page=1)

**FTP** look for the word games in content of open ftp with anonymous user

``` type:ftp ftp.user:anonymous ftp.names:"games" ``` [⏩](https://app.binaryedge.io/services/query?query=type:ftp%20ftp.user:anonymous%20ftp.names:%22games%22&page=1)

**RSYNC** - look for the word Linux on the content of open rsync servers

``` type:rsync rsync.banner:linux``` [⏩](https://app.binaryedge.io/services/query?query=type:rsync%20rsync.banner:linux&page=1)

# Queries - Images tab

Looking for RDNS

```rdns_parent:verizon.com``` [⏩](https://app.binaryedge.io/services/images?query=rdns_parent:uminho.pt&page=1)

Looking for VNC in the United states

```tags:"vnc" country:US``` [⏩](https://app.binaryedge.io/services/images?query=tags:%22vnc%22%20country:US&page=1)

Looking for hacked machines - this uses our OCR system

```hacked``` [⏩](https://app.binaryedge.io/services/images?query=hacked&page=1)

Looking for RDP in a specific ASN

``` asn:"16276" tags:"rdp" ``` [⏩](https://app.binaryedge.io/services/images?query=asn:%2216276%22%20tags:%22rdp%22&page=1)


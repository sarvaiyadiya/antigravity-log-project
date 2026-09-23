#!/usr/bin/env python3
"""
SIH Security Log Dataset Generator
====================================
Generates a realistic synthetic security log dataset for testing the
Universal Log Pre-processing Framework (ULPF) pipeline end-to-end.

14 attack campaigns are embedded as *behavioral sequences* across 12 log formats.
NO explicit attack labels appear in the raw log lines.

Output
------
  test_data/sih_security_logs_small.log   ~8,000 events
  test_data/sih_attack_ground_truth.json  campaign metadata + line numbers
"""

from __future__ import annotations

import base64
import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable

random.seed(42)

BASE_TIME = datetime(2024, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
_SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
OUTPUT_DIR    = os.path.join(_PROJECT_ROOT, "test_data")
os.makedirs(OUTPUT_DIR, exist_ok=True)
SMALL_LOG_PATH = os.path.join(OUTPUT_DIR, "sih_security_logs_small.log")
GT_PATH        = os.path.join(OUTPUT_DIR, "sih_attack_ground_truth.json")

# =============================================================================
# POOLS
# =============================================================================
INTERNAL_HOSTS = [
    "10.0.0.10","10.0.0.11","10.0.0.12","10.0.0.20","10.0.0.21",
    "10.0.0.30","10.0.0.31","10.0.0.50","10.0.0.55","10.0.0.60",
    "10.0.0.70","10.0.0.75","10.0.0.80","10.0.0.90",
    "192.168.1.10","192.168.1.20","172.16.0.5","172.16.0.20",
]
HOSTNAME_MAP = {
    "10.0.0.10":"dc01.corp.local","10.0.0.11":"dc02.corp.local",
    "10.0.0.12":"fileserver.corp.local","10.0.0.20":"webserver01.corp.local",
    "10.0.0.21":"webserver02.corp.local","10.0.0.30":"appserver01.corp.local",
    "10.0.0.31":"dbserver01.corp.local","10.0.0.50":"workstation-fin-01.corp.local",
    "10.0.0.55":"workstation-dev-05.corp.local","10.0.0.60":"workstation-it-03.corp.local",
    "10.0.0.70":"vpn-gw.corp.local","10.0.0.75":"workstation-ctr-01.corp.local",
    "10.0.0.80":"workstation-hr-02.corp.local","10.0.0.90":"mgmt-server.corp.local",
    "172.16.0.5":"backup-server.corp.local","172.16.0.20":"dns-server.corp.local",
}
BENIGN_EXT   = ["8.8.8.8","1.1.1.1","208.67.222.222","104.16.123.96",
                "172.217.14.78","151.101.1.140","93.184.216.34","17.253.144.10"]
INT_USERS    = ["jdoe","alice","bob","charlie","sysadm","webadm","dbadm","backup_svc"]
PAN_APPS     = ["web-browsing","ssl","ssh","dns","smtp","ftp","rdp","smb","unknown-tcp","ping"]
USER_AGENTS  = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "curl/7.68.0","python-requests/2.28.1",
]
HTTP_PATHS   = ["/","/index.html","/api/users","/api/products","/api/orders",
                "/static/js/main.js","/favicon.ico","/api/health","/login","/dashboard"]
HTTP_STATUS  = [200]*10+[201,204,301,304,400,401,403,404,500]
AWS_ACTIONS  = ["DescribeInstances","ListBuckets","GetObject","PutObject","DescribeSecurityGroups"]
AWS_USERS    = ["SvcDeployment","AdminUser","DataPipeline","MonitoringAgent"]
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,445,1433,1521,3306,3389,5432,5900,8080,8443]
DDOS_SRCS    = [f"100.64.{i}.{j}" for i in range(10) for j in range(2,30)]

def _hn(ip): return HOSTNAME_MAP.get(ip, ip)
def _ep(): return random.randint(49152,65535)
def _d(lo,hi): return timedelta(seconds=random.uniform(lo,hi))

# =============================================================================
# TIMESTAMP HELPERS
# =============================================================================
def ts_iso(d): return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z"
def ts_sl(d):  return d.strftime("%b %d %H:%M:%S").replace(" 0","  ")
def ts_csc(d): return d.strftime("%b %d %Y %H:%M:%S")
def ts_pan(d): return d.strftime("%Y/%m/%d %H:%M:%S")
def ts_win(d): return d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"000Z"
def ts_sn(d):  return d.strftime("%m/%d-%H:%M:%S.%f")[:-3]
def ts_csv(d): return d.strftime("%Y-%m-%d %H:%M:%S")

# =============================================================================
# SYSLOG RFC 3164   <PRI>Mon DD HH:MM:SS HOST TAG[PID]: MSG
# =============================================================================
def _sl(pri,dt,host,tag,pid,msg):
    return f"<{pri}>{ts_sl(dt)} {host} {tag}[{pid}]: {msg}"

def gen_syslog_benign(dt):
    host=random.choice(list(HOSTNAME_MAP.values()))
    user=random.choice(INT_USERS); ip=random.choice(BENIGN_EXT+INTERNAL_HOSTS[:8])
    pid=random.randint(1000,60000); pri=random.choice([38,30,134,29])
    msgs=[
        f"Accepted publickey for {user} from {ip} port {_ep()} ssh2",
        f"session opened for user {user} by (uid=0)",
        f"session closed for user {user}",
        f"Connection from {ip} port {_ep()}",
        f"cron[{pid}]: ({user}) CMD (/usr/bin/updatedb)",
        f"ntpd: synchronized to {ip}, stratum 3",
        f"postfix/smtp: message-id=<{user}@corp.local>: delivered",
    ]
    return _sl(pri,dt,host,random.choice(["sshd","cron","kernel","postfix","ntpd"]),pid,random.choice(msgs))

def gen_sl_auth_fail(dt,src,host,user):
    return _sl(36,dt,host,"sshd",random.randint(1000,60000),
               f"Failed password for {user} from {src} port {_ep()} ssh2")

def gen_sl_auth_ok(dt,src,host,user):
    return _sl(38,dt,host,"sshd",random.randint(1000,60000),
               f"Accepted password for {user} from {src} port {_ep()} ssh2")

def gen_sl_sudo(dt,host,user,cmd):
    return _sl(35,dt,host,"sudo",random.randint(1000,60000),
               f"{user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND={cmd}")

def gen_sl_dns(dt,qname,client):
    return _sl(30,dt,"dns-server.corp.local","named",random.randint(1000,60000),
               f"client {client}#53: query: {qname} IN TXT + (127.0.0.1)")

def gen_sl_file(dt,host,user,path):
    ts_raw=int(dt.timestamp()*1000)
    return _sl(35,dt,host,"kernel",random.randint(1000,60000),
               f'audit: type=PATH msg=audit({ts_raw}:100): name="{path}" inode=12345 nametype=WRITE uid=0 auid=1000')

def gen_sl_proxy(dt,src,dst,domain,size):
    return _sl(134,dt,"squid-proxy.corp.local","squid",random.randint(1000,60000),
               f"TCP_MISS/200 {size} GET http://{domain}/gate.php - DIRECT/{dst} application/octet-stream SRC:{src}")

# =============================================================================
# WINDOWS EVENT XML  (single-line)
# =============================================================================
_WIN_NS="http://schemas.microsoft.com/win/2004/08/events/event"

def gen_win_evt(dt,eid,subj,tgt,src_ip,*,domain="CORP",ltype=3,status="0x0",
                obj="",proc="explorer.exe"):
    pid=random.randint(4,9999); tid=random.randint(100,9999)
    rec=random.randint(100000,9999999); host=random.choice(["CORPDC01","CORPDC02","CORPWKS01"])
    if eid==4625:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="TargetUserName">{tgt}</Data>'
            f'<Data Name="Status">{status}</Data>'
            f'<Data Name="LogonType">{ltype}</Data>'
            f'<Data Name="IpAddress">{src_ip}</Data>'
            f'<Data Name="IpPort">{_ep()}</Data>'
            f'<Data Name="FailureReason">%%2313</Data>')
    elif eid==4624:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="TargetUserName">{tgt}</Data>'
            f'<Data Name="LogonType">{ltype}</Data>'
            f'<Data Name="IpAddress">{src_ip}</Data>'
            f'<Data Name="IpPort">{_ep()}</Data>')
    elif eid==4648:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="SubjectDomainName">{domain}</Data>'
            f'<Data Name="TargetUserName">{tgt}</Data>'
            f'<Data Name="TargetServerName">{src_ip}</Data>'
            f'<Data Name="IpAddress">{src_ip}</Data>')
    elif eid==4672:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="SubjectDomainName">{domain}</Data>'
            f'<Data Name="PrivilegeList">SeSecurityPrivilege SeDebugPrivilege</Data>')
    elif eid==4663:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="ObjectName">{obj}</Data>'
            f'<Data Name="ObjectType">File</Data>'
            f'<Data Name="AccessList">%%4416 %%4417</Data>'
            f'<Data Name="ProcessName">{proc}</Data>')
    elif eid==4688:
        ed=(f'<Data Name="SubjectUserName">{subj}</Data>'
            f'<Data Name="NewProcessName">{proc}</Data>'
            f'<Data Name="CommandLine">{obj}</Data>')
    else:
        ed=f'<Data Name="SubjectUserName">{subj}</Data><Data Name="TargetUserName">{tgt}</Data>'
    return (f'<Event xmlns="{_WIN_NS}"><System>'
            f'<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>'
            f'<EventID>{eid}</EventID><Version>0</Version><Level>0</Level><Task>12544</Task>'
            f'<Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime="{ts_win(dt)}"/>'
            f'<EventRecordID>{rec}</EventRecordID>'
            f'<Execution ProcessID="{pid}" ThreadID="{tid}"/>'
            f'<Channel>Security</Channel><Computer>{host}</Computer></System>'
            f'<EventData>{ed}</EventData></Event>')

def gen_win_benign(dt):
    u=random.choice(INT_USERS); s=random.choice(INTERNAL_HOSTS[:8])
    return gen_win_evt(dt,random.choice([4624,4634,4688]),u,u,s,ltype=2)

# =============================================================================
# JSON
# =============================================================================
def gen_json_web(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:4])
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,
        "dst_ip":random.choice(["10.0.0.20","10.0.0.21"]),"src_port":_ep(),
        "dst_port":random.choice([80,443]),"method":random.choices(["GET","POST","PUT"],[6,3,1])[0],
        "path":random.choice(HTTP_PATHS),"status":random.choice(HTTP_STATUS),
        "bytes":random.randint(200,50000),"user_agent":random.choice(USER_AGENTS),
        "duration_ms":random.randint(5,500),"server":"nginx/1.21.6"})

def gen_json_sqli(dt,src):
    pls=["' OR '1'='1","1' UNION SELECT NULL,username,password FROM users--",
         "'; DROP TABLE users;--","1 AND 1=1--","admin'--",
         "' UNION SELECT 1,2,3--","1; SELECT * FROM information_schema.tables"]
    ep=random.choice(["products","users","orders","login","account"])
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,"dst_ip":"10.0.0.20",
        "src_port":_ep(),"dst_port":80,"method":random.choice(["GET","POST"]),
        "path":f"/api/{ep}?id={random.choice(pls)}","status":random.choice([200,500,403]),
        "bytes":random.randint(100,5000),"user_agent":random.choice(USER_AGENTS),
        "duration_ms":random.randint(1,3000),"server":"nginx/1.21.6"})

def gen_json_c2(dt,src,c2,domain):
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,"dst_ip":c2,
        "src_port":_ep(),"dst_port":random.choice([80,443,8080]),"method":"GET",
        "path":f"/gate.php?hwid={random.randint(10000,99999)}&ver=2.1","host":domain,
        "status":200,"bytes":random.randint(128,512),
        "user_agent":"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "duration_ms":random.randint(80,300),"proxy":"squid/4.13"})

def gen_json_exfil(dt,src,dst):
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,"dst_ip":dst,
        "src_port":_ep(),"dst_port":443,"protocol":"HTTPS",
        "bytes_out":random.randint(5_000_000,50_000_000),
        "bytes_in":random.randint(1000,5000),"duration_s":random.randint(10,120),
        "action":"allow","application":"ssl"})

def gen_json_dns(dt,src,qname):
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,"dst_ip":"172.16.0.20",
        "query":qname,"query_type":random.choice(["TXT","A","CNAME"]),
        "response_code":random.choice(["NOERROR","NXDOMAIN"]),
        "response_time_ms":random.randint(100,2000),
        "bytes":len(qname)+random.randint(50,200)})

def gen_json_lfi(dt,src):
    pls=["/../../../etc/passwd","/../../../etc/shadow","/%2e%2e%2fetc%2fpasswd",
         "/<script>alert(document.cookie)</script>","/\"'><img src=x onerror=alert(1)>","/../boot.ini"]
    return json.dumps({"timestamp":ts_iso(dt),"src_ip":src,"dst_ip":"10.0.0.20",
        "method":"GET","path":f"/api/file?path={random.choice(pls)}",
        "status":random.choice([200,403,404,500]),"bytes":random.randint(100,8096),
        "user_agent":random.choice(USER_AGENTS),"duration_ms":random.randint(1,100),
        "server":"nginx/1.21.6"})

def gen_json_auth_fail(dt,src,uname):
    return json.dumps({"timestamp":ts_iso(dt),"event":"auth_failure","src_ip":src,
        "username":uname,"reason":"invalid_password","app":"corporate-portal",
        "session_id":f"{random.randint(0,0xFFFFFFFF):08x}"})

def gen_json_cloudtrail(dt):
    u=random.choice(AWS_USERS); a=random.choice(AWS_ACTIONS)
    return json.dumps({"eventVersion":"1.08",
        "userIdentity":{"type":"IAMUser","userName":u,"arn":f"arn:aws:iam::123456789012:user/{u}"},
        "eventTime":ts_iso(dt),"eventSource":"ec2.amazonaws.com","eventName":a,
        "awsRegion":random.choice(["us-east-1","eu-west-1"]),
        "sourceIPAddress":random.choice(INTERNAL_HOSTS[:8]),
        "userAgent":"aws-cli/2.11.0 Python/3.11.4",
        "requestParameters":{"maxResults":100},"responseElements":None,
        "requestID":f"{random.randint(0,0xFFFFFFFF):08x}",
        "eventID":f"{random.randint(0,0xFFFFFFFF):08x}",
        "eventType":"AwsApiCall","recipientAccountId":"123456789012"})

# =============================================================================
# CISCO ASA   (%ASA-N-MSGID: ...)
# =============================================================================
def gen_csc_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:5])
    dst=random.choice(INTERNAL_HOSTS[:5]); proto=random.choice(["tcp","udp"])
    sp=_ep(); dp=random.choice(COMMON_PORTS); sev=random.choice([4,5,6])
    act,mid=random.choice([("Permit","302013"),("Permit","106100"),("Deny","106023")])
    return f"{ts_csc(dt)}: %ASA-{sev}-{mid}: {act} {proto} src outside:{src}/{sp} dst inside:{dst}/{dp} by access-group \"outside_access_in\" [0x0, 0x0]"

def gen_csc_deny(dt,src,dst,dport,proto="tcp"):
    return f"{ts_csc(dt)}: %ASA-4-106023: Deny {proto} src outside:{src}/{_ep()} dst inside:{dst}/{dport} by access-group \"outside_access_in\" [0x0, 0x0]"

def gen_csc_teardown(dt,src,dst,dport,nbytes):
    cid=random.randint(100000,999999)
    return f"{ts_csc(dt)}: %ASA-6-302014: Teardown TCP connection {cid} for outside:{src}/{_ep()} to inside:{dst}/{dport} duration 0:01:30 bytes {nbytes} Reset"

# =============================================================================
# CEF
# =============================================================================
def gen_cef_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:5]); dst=random.choice(INTERNAL_HOSTS[:5])
    user=random.choice(INT_USERS); sev=random.randint(1,4); rt=int(dt.timestamp()*1000)
    k,n,ext=random.choice([
        (100,"Network_Connection",f"src={src} dst={dst} spt={_ep()} dpt={random.choice(COMMON_PORTS)} proto=TCP act=allow"),
        (200,"User_Auth_Success",f"src={src} suser={user} outcome=success"),
        (300,"DNS_Query",f"src={src} request=www.google.com requestContext=A"),
    ])
    return f"CEF:0|CorpSIEM|Endpoint|1.0|{k}|{n}|{sev}|rt={rt} {ext}"

def gen_cef_sqli(dt,src):
    pls=["' OR 1=1--","UNION SELECT NULL,NULL--","'; DROP TABLE--"]
    rt=int(dt.timestamp()*1000)
    return f"CEF:0|CorpWAF|WAF|1.0|1001|SQL_Injection_Attempt|8|rt={rt} src={src} dst=10.0.0.20 spt={_ep()} dpt=80 request=/api/products?id={random.choice(pls)} act=detect cs1Label=WAFRule cs1=WEB_ATTACK_SQL_INJECTION"

def gen_cef_c2(dt,src,c2):
    rt=int(dt.timestamp()*1000)
    return f"CEF:0|CorpProxy|ProxyNG|1.0|5001|Suspicious_Outbound|7|rt={rt} src={src} dst={c2} spt={_ep()} dpt=443 bytesOut={random.randint(200,800)} bytesIn={random.randint(100,500)} requestMethod=GET cs1Label=Category cs1=Uncategorized"

def gen_cef_ddos(dt,src,dst):
    rt=int(dt.timestamp()*1000)
    return f"CEF:0|CorpFW|NGFW|1.0|9001|High_Volume_Traffic|9|rt={rt} src={src} dst={dst} dpt=80 cnt={random.randint(500,5000)} proto=TCP act=block cs1Label=ThreatType cs1=DDoS"

def gen_cef_lfi(dt,src):
    rt=int(dt.timestamp()*1000); pls=["/../../../etc/passwd","/%2e%2e%2fetc%2fpasswd","/../boot.ini"]
    return f"CEF:0|CorpWAF|WAF|1.0|1005|Path_Traversal_Attempt|8|rt={rt} src={src} dst=10.0.0.20 spt={_ep()} dpt=80 request={random.choice(pls)} act=detect cs1Label=WAFRule cs1=WEB_ATTACK_LFI"

def gen_cef_zero_day(dt,src):
    rt=int(dt.timestamp()*1000)
    return f"CEF:0|CorpIDS|NGIDS|2.0|9999|Possible_Zero_Day_Exploit|10|rt={rt} src={src} dst=10.0.0.20 spt={_ep()} dpt=443 proto=TCP cs1Label=CVE cs1=CVE-2024-UNKNOWN cs2Label=Payload cs2=oversized_malformed_tls_clienthello"

# =============================================================================
# PALO ALTO  (CSV, field[3]="TRAFFIC", >=30 fields)
# Parser reads: f[1]=ts, f[7]=src, f[8]=dst, f[11]=rule, f[12]=user, f[14]=app
#               f[16]=srczone, f[17]=dstzone, f[24]=sport, f[25]=dport
#               f[29]=proto, f[30]=action, f[38]=bytes_sent, f[39]=bytes_recv, f[40]=pkts
# =============================================================================
def _pan(dt,src,dst,sp,dp,proto,action,app,sz,dz,rule,bs,br):
    pt=ts_pan(dt); serial="007200001"; sess=random.randint(100000,999999)
    pkts=max(1,bs//random.randint(800,1500)); elapsed=random.randint(1,300)
    f=[""]*45
    f[0]="";f[1]=pt;f[2]=serial;f[3]="TRAFFIC";f[4]="end";f[5]="2048"
    f[6]=pt;f[7]=src;f[8]=dst;f[9]="";f[10]=""
    f[11]=rule;f[12]="unknown";f[13]="unknown";f[14]=app;f[15]="vsys1"
    f[16]=sz;f[17]=dz;f[18]="ethernet1/1";f[19]="ethernet1/2"
    f[20]="default";f[21]="";f[22]=str(sess);f[23]="1"
    f[24]=str(sp);f[25]=str(dp);f[26]=str(sp);f[27]=str(dp)
    f[28]="0x400000";f[29]=proto;f[30]=action
    f[31]=str(bs+br);f[32]="";f[33]="";f[34]=str(pkts);f[35]=pt
    f[36]=str(elapsed);f[37]="general-internet"
    f[38]=str(bs);f[39]=str(br);f[40]=str(pkts)
    f[41]="";f[42]="";f[43]=serial;f[44]="from-policy"
    return ",".join(f)

def gen_pan_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:5]); dst=random.choice(INTERNAL_HOSTS[:5])
    return _pan(dt,src,dst,_ep(),random.choice(COMMON_PORTS),"tcp","allow",
                random.choice(PAN_APPS),"trust","trust","internet-access",
                random.randint(500,100000),random.randint(200,50000))

def gen_pan_scan(dt,src,dst,dp):
    return _pan(dt,src,dst,_ep(),dp,"tcp","deny","unknown-tcp","untrust","trust","block-scan",52,0)

def gen_pan_exfil(dt,src,dst,bs):
    return _pan(dt,src,dst,_ep(),443,"tcp","allow","ssl","trust","untrust","internet-access",bs,random.randint(1000,5000))

# =============================================================================
# SNORT  (fast format: MM/DD-HH:MM:SS.ffffff  [**] [G:S:R] MSG [**] [Class] [Prio] {PROTO} s:sp -> d:dp)
# =============================================================================
def _sn(dt,gid,sid,rev,msg,cl,pri,proto,src,sp,dst,dp):
    return f"{ts_sn(dt)}  [**] [{gid}:{sid}:{rev}] {msg} [**] [Classification: {cl}] [Priority: {pri}] {{{proto}}} {src}:{sp} -> {dst}:{dp}"

def gen_sn_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:5]); dst=random.choice(INTERNAL_HOSTS[:5])
    rules=[(1,1000001,1,"ET INFO DNS Query to .tech TLD","Potentially Bad Traffic",3,"TCP"),
           (1,1000002,1,"ET POLICY HTTP on port 8080","Potentially Bad Traffic",3,"TCP"),
           (1,1000003,1,"ET INFO TLS X.509 Cert Observed","Potentially Bad Traffic",4,"TCP")]
    g,s,r,m,c,p,pr=random.choice(rules)
    return _sn(dt,g,s,r,m,c,p,pr,src,_ep(),dst,random.choice(COMMON_PORTS))

def gen_sn_scan(dt,src,dst,dp):
    return _sn(dt,1,2001569,7,"ET SCAN Potential SSH Scan OUTBOUND","Attempted Information Leak",2,"TCP",src,_ep(),dst,dp)

def gen_sn_sqli(dt,src):
    return _sn(dt,1,2006445,3,"ET WEB_SERVER SQL Injection Attempt","Web Application Attack",1,"TCP",src,_ep(),"10.0.0.20",80)

def gen_sn_lfi(dt,src):
    return _sn(dt,1,2101893,5,"ET WEB_ATTACK PHP Remote File Include Attempt","Web Application Attack",1,"TCP",src,_ep(),"10.0.0.20",80)

def gen_sn_zeroday(dt,src):
    return _sn(dt,1,2025969,1,"ET EXPLOIT Possible Zero-Day Malformed TLS ClientHello","Attempted User Privilege Gain",1,"TCP",src,_ep(),"10.0.0.20",443)

# =============================================================================
# LEEF
# =============================================================================
def gen_leef_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]); user=random.choice(INT_USERS); rt=int(dt.timestamp()*1000)
    k,attrs=random.choice([
        ("UserLogin",f"src={src}\tusrName={user}\toutcome=success"),
        ("FileAccess",f"src={src}\tusrName={user}\tresource=/data/report.pdf\taccess=READ"),
        ("NetworkConnect",f"src={src}\tdst={random.choice(BENIGN_EXT)}\tproto=TCP\tdstPort={random.choice(COMMON_PORTS)}"),
    ])
    return f"LEEF:2.0|IBM|QRadar SIEM|7.5|{k}|devTime={rt}\t{attrs}"

# =============================================================================
# CSV
# =============================================================================
def gen_csv_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]+BENIGN_EXT[:5]); dst=random.choice(INTERNAL_HOSTS[:5])
    return f"{ts_csv(dt)},{src},{dst},{_ep()},{random.choice(COMMON_PORTS)},{random.choice(['TCP','UDP'])},{random.randint(100,50000)},{random.randint(100,10000)},{random.randint(1,300)},allow,{random.choice(PAN_APPS)}"

# =============================================================================
# GENERIC XML (single line)
# =============================================================================
def gen_xml_benign(dt):
    src=random.choice(INTERNAL_HOSTS[:10]); user=random.choice(INT_USERS)
    etype=random.choice(["NetworkConnection","FileOperation","UserActivity"])
    return f'<logentry><timestamp>{ts_iso(dt)}</timestamp><event_type>{etype}</event_type><source_ip>{src}</source_ip><user>{user}</user><result>success</result><details>Routine operation</details></logentry>'

# =============================================================================
# MALFORMED
# =============================================================================
_MAL=[
    lambda d: f"<38>{ts_sl(d)} host sshd[",
    lambda d: '{"timestamp": "'+ts_iso(d)+'", "src_ip": "10.0.0.',
    lambda d: "LEEF:2.0|IBM|",
    lambda d: f"{ts_csc(d)}: %ASA-4-",
    lambda d: f'<logentry><timestamp>{ts_iso(d)}</timestamp><event_type>',
    lambda d: "",
    lambda d: "CEF:99|Vendor|Product|ver|100|Event|5|incomplete",
    lambda d: "A"*random.randint(2000,4000),
    lambda d: f"\x00\x00<38>{ts_sl(d)} host: null_bytes_injected",
]
def gen_malformed(dt): return random.choice(_MAL)(dt)

# =============================================================================
# FORMAT WEIGHTS
# =============================================================================
_FW={"syslog":30,"windows_xml":18,"json":15,"cisco_asa":10,"cef":8,
     "paloalto":7,"snort":5,"leef":3,"cloudtrail":2,"csv":1.5,"xml":0.5}
_FN=list(_FW.keys()); _FP=[_FW[f]/sum(_FW.values()) for f in _FN]
def _fmt(): return random.choices(_FN,weights=_FP,k=1)[0]

# =============================================================================
# BENIGN TRAFFIC
# =============================================================================
def gen_benign(n):
    hw=[1,1,1,1,2,3,4,6,10,12,12,12,12,12,12,12,12,10,8,6,5,4,3,2]
    events=[]
    for _ in range(n):
        h=random.choices(range(24),weights=hw)[0]
        dt=BASE_TIME+timedelta(hours=h,minutes=random.randint(0,59),
                               seconds=random.randint(0,59),microseconds=random.randint(0,999999))
        f=_fmt()
        if f=="syslog":       line=gen_syslog_benign(dt)
        elif f=="windows_xml":line=gen_win_benign(dt)
        elif f=="json":       line=gen_json_web(dt)
        elif f=="cisco_asa":  line=gen_csc_benign(dt)
        elif f=="cef":        line=gen_cef_benign(dt)
        elif f=="paloalto":   line=gen_pan_benign(dt)
        elif f=="snort":      line=gen_sn_benign(dt)
        elif f=="leef":       line=gen_leef_benign(dt)
        elif f=="cloudtrail": line=gen_json_cloudtrail(dt)
        elif f=="csv":        line=gen_csv_benign(dt)
        else:                 line=gen_xml_benign(dt)
        events.append((dt,line,None))
    return events

# =============================================================================
# ATTACK CAMPAIGNS
# =============================================================================

def c_brute_force(s):
    cid="bf_001"; src="203.0.113.45"; tgt="10.0.0.20"; host=_hn(tgt)
    users=["root","admin","ubuntu","ec2-user","jdoe","alice","vagrant","pi"]
    ev=[]; dt=s
    for i in range(55):
        ev.append((dt,gen_sl_auth_fail(dt,src,host,users[i%len(users)]),cid))
        if i%5==0: ev.append((dt+_d(.05,.1),gen_csc_deny(dt,src,tgt,22),cid))
        dt+=_d(1,3)
    ev.append((dt,gen_sl_auth_ok(dt,src,host,"jdoe"),cid))
    return ev,cid,src,tgt,s,dt

def c_port_scan(s):
    cid="scan_001"; src="198.51.100.77"; tgt="10.0.0.20"
    ports=[21,22,23,25,53,80,110,143,443,445,512,513,514,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017,11211,6667,4444,1080]
    ev=[]; dt=s
    for p in ports:
        ev.append((dt,gen_csc_deny(dt,src,tgt,p),cid))
        ev.append((dt+_d(.01,.05),gen_pan_scan(dt,src,tgt,p),cid))
        if p%7==0: ev.append((dt+_d(.05,.1),gen_sn_scan(dt,src,tgt,p),cid))
        dt+=_d(.1,.5)
    return ev,cid,src,tgt,s,dt

def c_sql_injection(s):
    cid="sqli_001"; src="192.0.2.111"; ev=[]; dt=s
    for i in range(35):
        ev.append((dt,gen_json_sqli(dt,src),cid))
        if i%3==0: ev.append((dt+_d(.005,.02),gen_cef_sqli(dt,src),cid))
        if i%5==0: ev.append((dt+_d(.01,.05),gen_sn_sqli(dt,src),cid))
        dt+=_d(2,15)
    return ev,cid,src,"10.0.0.20",s,dt

def c_c2_beaconing(s):
    cid="c2_001"; src="10.0.0.50"; c2="185.220.101.7"
    domain="updates.microsoftservices-cdn.com"; ev=[]; dt=s
    for i in range(90):
        ev.append((dt,gen_json_c2(dt,src,c2,domain),cid))
        if i%10==0: ev.append((dt+_d(.05,.1),gen_cef_c2(dt,src,c2),cid))
        if i%15==0: ev.append((dt,gen_sl_proxy(dt,src,c2,domain,random.randint(200,800)),cid))
        dt+=_d(55,65)
    return ev,cid,src,c2,s,dt

def c_privesc(s):
    cid="privesc_001"; user="jdoe"; host_ip="10.0.0.30"; host=_hn(host_ip)
    ev=[]; dt=s
    ev.append((dt,gen_sl_auth_ok(dt,"10.0.0.55",host,user),cid)); dt+=_d(5,20)
    for cmd in ["/bin/bash","/usr/bin/python3 /tmp/esc.py","/usr/sbin/useradd -o -u 0 backdoor","/usr/bin/id"]:
        ev.append((dt,gen_sl_sudo(dt,host,user,cmd),cid)); dt+=_d(2,8)
    ev.append((dt,gen_win_evt(dt,4672,user,user,host_ip),cid)); dt+=_d(1,5)
    for p in ["/etc/shadow","/etc/passwd","/root/.ssh/id_rsa","/var/backup/db.dump"]:
        ev.append((dt,gen_sl_file(dt,host,user,p),cid)); dt+=_d(1,5)
    return ev,cid,user,host_ip,s,dt

def c_exfil(s):
    cid="exfil_001"; src="10.0.0.55"; dst="91.108.4.1"; ev=[]; dt=s
    for _ in range(20):
        nb=random.randint(5_000_000,50_000_000)
        ev.append((dt,gen_json_exfil(dt,src,dst),cid))
        ev.append((dt+_d(10,30),gen_csc_teardown(dt,src,dst,443,nb),cid))
        ev.append((dt+_d(30,60),gen_pan_exfil(dt,src,dst,nb),cid))
        dt+=_d(30,120)
    return ev,cid,src,dst,s,dt

def c_lateral(s):
    cid="lateral_001"; src="10.0.0.45"; user="sysadm"
    tgts=["10.0.0.10","10.0.0.11","10.0.0.12","10.0.0.30","10.0.0.31","10.0.0.90"]
    ev=[]; dt=s
    for tgt in tgts:
        for _ in range(random.randint(2,5)):
            ev.append((dt,gen_win_evt(dt,4625,user,user,src,status="0xC000006D"),cid)); dt+=_d(1,5)
        ev.append((dt,gen_win_evt(dt,4624,user,user,src,ltype=3),cid))
        ev.append((dt+_d(.5,2),gen_win_evt(dt,4648,user,f"Admin@{_hn(tgt)}",tgt),cid))
        dt+=_d(20,60)
    return ev,cid,src,tgts,s,dt

def c_dns_tunnel(s):
    cid="dns_tunnel_001"; src="10.0.0.60"; tdomain="exfil.evil-c2.net"; ev=[]; dt=s
    for i in range(200):
        chunk=base64.b64encode(os.urandom(random.randint(20,40))).decode()
        chunk=chunk.replace("=","").replace("+","x").replace("/","y").lower()
        qname=f"{chunk}.{tdomain}"
        ev.append((dt,gen_sl_dns(dt,qname,src),cid))
        if i%3==0: ev.append((dt+_d(.05,.1),gen_json_dns(dt,src,qname),cid))
        dt+=_d(.5,3)
    return ev,cid,src,tdomain,s,dt

def c_webapp(s):
    cid="webapp_001"; src="203.0.113.88"; ev=[]; dt=s
    for i in range(45):
        ev.append((dt,gen_json_lfi(dt,src),cid))
        if i%3==0: ev.append((dt+_d(.005,.02),gen_cef_lfi(dt,src),cid))
        if i%6==0: ev.append((dt+_d(.01,.05),gen_sn_lfi(dt,src),cid))
        dt+=_d(1,10)
    return ev,cid,src,"10.0.0.20",s,dt

def c_ddos(s):
    cid="ddos_001"; tgt="10.0.0.20"; ev=[]; dt=s
    for i in range(300):
        src=random.choice(DDOS_SRCS)
        ev.append((dt,gen_cef_ddos(dt,src,tgt),cid))
        if i%3==0: ev.append((dt+_d(.001,.01),gen_csc_deny(dt,src,tgt,80),cid))
        if i%5==0: ev.append((dt+_d(.002,.02),gen_pan_scan(dt,src,tgt,80),cid))
        dt+=_d(.05,.2)
    return ev,cid,"multiple_ips",tgt,s,dt

def c_insider(s):
    cid="insider_001"; user="contractor01"; ws="10.0.0.75"
    dt=s.replace(hour=3,minute=0,second=0,microsecond=0); ev=[]
    ev.append((dt,gen_win_evt(dt,4624,user,user,ws,ltype=2),cid)); dt+=_d(5,30)
    for share in [r"\\fileserver\HR\salary_data",r"\\fileserver\Finance\Q4_Reports",
                  r"\\fileserver\Legal\contracts",r"\\fileserver\IT\credentials"]:
        for _ in range(random.randint(10,20)):
            fname=f"{share}\\report_{random.randint(1,999):03d}.xlsx"
            ev.append((dt,gen_win_evt(dt,4663,user,user,ws,obj=fname,proc=r"C:\Windows\explorer.exe"),cid))
            dt+=_d(.5,3)
    for _ in range(15):
        ev.append((dt,gen_json_exfil(dt,ws,"10.0.0.90"),cid)); dt+=_d(5,20)
    return ev,cid,user,ws,s.replace(hour=3),dt

def c_credstuff(s):
    cid="credstuff_001"; src="198.51.100.200"
    accounts=[f"user{i:04d}" for i in range(1,51)]; ev=[]; dt=s
    for acct in accounts:
        for _ in range(random.randint(1,3)):
            ev.append((dt,gen_win_evt(dt,4625,acct,acct,src,status="0xC000006D"),cid)); dt+=_d(.5,2)
        ev.append((dt,gen_json_auth_fail(dt,src,f"{acct}@corp.local"),cid)); dt+=_d(.5,3)
    return ev,cid,src,"corp-auth",s,dt

def c_ransomware(s):
    cid="ransom_001"; user="jdoe"; ws="10.0.0.80"; ev=[]; dt=s
    dirs=[r"C:\Users",r"D:\Shares",r"\\fileserver\public",r"C:\ProgramData"]
    for _ in range(40):
        dpath=f"{random.choice(dirs)}\\{random.randint(1000,9999)}"
        ev.append((dt,gen_win_evt(dt,4663,user,user,ws,obj=dpath,proc=r"C:\Windows\System32\cmd.exe"),cid)); dt+=_d(.1,.5)
    exts=[".docx",".xlsx",".pdf",".pptx",".txt",".csv",".db"]
    for _ in range(60):
        name=f"D:\\Shares\\finance\\data_{random.randint(1,9999):04d}{random.choice(exts)}"
        ev.append((dt,gen_win_evt(dt,4663,user,user,ws,obj=name,proc=r"C:\malware\locker.exe"),cid)); dt+=_d(.05,.2)
    for _ in range(30):
        enc=f"D:\\Shares\\finance\\report_{random.randint(1,999):03d}.xlsx.ENCRYPTED"
        ev.append((dt,gen_sl_file(dt,"fileserver.corp.local",user,enc),cid)); dt+=_d(.05,.2)
    return ev,cid,user,ws,s,dt

def c_zeroday(s):
    cid="zeroday_001"; src="185.220.101.100"; dst="10.0.0.20"; ev=[]; dt=s
    for _ in range(12): ev.append((dt,gen_sn_zeroday(dt,src),cid)); dt+=_d(1,5)
    for _ in range(8):  ev.append((dt,gen_cef_zero_day(dt,src),cid)); dt+=_d(.5,3)
    for _ in range(5):  ev.append((dt,gen_pan_exfil(dt,src,dst,random.randint(65535,131072)),cid)); dt+=_d(1,4)
    return ev,cid,src,dst,s,dt

# =============================================================================
# DETECTION HINTS
# =============================================================================
def _hints(cid):
    H={"bf_001":["55+ failed SSH auths from same IP within 3 min","Sequential user enumeration"],
       "scan_001":["30+ DST ports in <15s from same src IP","All connections denied"],
       "sqli_001":["SQL keywords in HTTP path (UNION SELECT, DROP TABLE)","Multiple 4xx/5xx responses"],
       "c2_001":["Regular 60s GET intervals to uncategorized domain","Old IE user-agent, tiny 128-512B payload"],
       "privesc_001":["SSH login -> rapid sudo commands -> /etc/shadow access","useradd uid=0"],
       "exfil_001":["5-50MB outbound per session to external IP","20 consecutive large TCP teardowns"],
       "lateral_001":["Same user auth failures then success across 6 hosts","Event 4648 across subnet"],
       "dns_tunnel_001":["50+ char base64-like subdomain queries","TXT records, high frequency from single host"],
       "webapp_001":["../etc/passwd or %2e%2e in URL path","XSS patterns: <script>, onerror= in request"],
       "ddos_001":["300+ src IPs targeting single IP:80 in 60s","All blocked, CEF cnt>500"],
       "insider_001":["4624 logon at 03:00 local","Contractor accessing HR/Finance shares en-masse"],
       "credstuff_001":["50+ unique account failures from single IP in 5 min","No repeated usernames"],
       "ransom_001":["Rapid 4663 via locker.exe process","File paths with .ENCRYPTED suffix writes"],
       "zeroday_001":["Snort sid 2025969 alerts","Oversized (>65535B) TCP payload to port 443"]}
    return H.get(cid,[])

# =============================================================================
# MAIN
# =============================================================================
def main():
    print("="*60)
    print("  SIH Security Log Dataset Generator v1.0")
    print("="*60)
    all_ev=[]
    gt={"metadata":{"generated_at":datetime.now(timezone.utc).isoformat(),
                     "base_date":str(BASE_TIME.date()),"generator_version":"1.0.0",
                     "detection_challenge":"Attacks encoded as behavioral sequences. No explicit labels."},
        "attack_campaigns":[]}

    schedule=[
        (c_brute_force,      2.50, "Brute Force SSH",        "T1110"),
        (c_port_scan,        4.75, "Port Scanning",           "T1046"),
        (c_sql_injection,    6.25, "SQL Injection",           "T1190"),
        (c_c2_beaconing,     1.00, "C2 Beaconing",            "T1071"),
        (c_privesc,          2.90, "Privilege Escalation",    "T1078"),
        (c_exfil,            9.50, "Data Exfiltration",       "T1041"),
        (c_lateral,         11.25, "Lateral Movement",        "T1021"),
        (c_dns_tunnel,       7.50, "DNS Tunneling",           "T1071"),
        (c_webapp,          13.50, "Web App Attack LFI/XSS",  "T1190"),
        (c_ddos,            15.00, "DDoS",                    "T1498"),
        (c_insider,          3.00, "Insider Threat",          "T1078"),
        (c_credstuff,       17.75, "Credential Stuffing",     "T1110"),
        (c_ransomware,      20.00, "Ransomware Staging",      "T1486"),
        (c_zeroday,         22.50, "Zero-Day Exploit",        "T1190"),
    ]

    atk_count=0
    for fn,off,desc,mitre in schedule:
        start=BASE_TIME+timedelta(hours=off)
        sys.stdout.write(f"  [{mitre}] {desc}... "); sys.stdout.flush()
        ev,cid,src,tgt,t0,t1=fn(start)
        all_ev.extend(ev); atk_count+=len(ev)
        gt["attack_campaigns"].append({
            "id":cid,"type":desc.lower().replace(" ","_").replace("/","_"),
            "description":desc,"mitre_technique":mitre,
            "start_time":t0.isoformat(),"end_time":t1.isoformat(),
            "source":str(src),"target":str(tgt),"event_count":len(ev),
            "line_numbers":[],"detection_indicators":_hints(cid)})
        print(f"{len(ev)} events")

    n_benign=int(atk_count*3)
    print(f"\n  Generating {n_benign} benign events...")
    all_ev.extend(gen_benign(n_benign))

    n_mal=max(80,int(len(all_ev)*.02))
    print(f"  Adding {n_mal} malformed log lines...")
    for _ in range(n_mal):
        h=random.randint(0,23)
        dt=BASE_TIME+timedelta(hours=h,minutes=random.randint(0,59),seconds=random.randint(0,59))
        all_ev.append((dt,gen_malformed(dt),None))

    total=len(all_ev)
    print(f"\n  Sorting {total:,} events by timestamp...")
    all_ev.sort(key=lambda e:e[0])

    camp_lines={}
    for ln,(dt2,line,cid) in enumerate(all_ev,start=1):
        if cid: camp_lines.setdefault(cid,[]).append(ln)
    for camp in gt["attack_campaigns"]:
        camp["line_numbers"]=camp_lines.get(camp["id"],[])

    print(f"  Writing {SMALL_LOG_PATH} ...")
    atk_lines=ben_lines=0
    with open(SMALL_LOG_PATH,"w",encoding="utf-8",errors="replace") as f:
        for _,line,cid in all_ev:
            try:   f.write((line or "")+"\n")
            except Exception: f.write("[MALFORMED LOG - STRIPPED]\n")
            if cid: atk_lines+=1
            else:   ben_lines+=1

    gt["metadata"].update({"total_events":total,"attack_events":atk_lines,
        "benign_events":ben_lines,"malformed_injected":n_mal,
        "attack_ratio":round(atk_lines/max(total,1),3),"output_file":SMALL_LOG_PATH,
        "format_distribution":{
            "syslog_pct":30,"windows_event_xml_pct":18,"json_pct":15,"cisco_asa_pct":10,
            "cef_pct":8,"paloalto_pct":7,"snort_pct":5,"leef_pct":3,
            "cloudtrail_pct":2,"csv_pct":1.5,"xml_pct":0.5,"malformed_pct":2}})

    print(f"  Writing {GT_PATH} ...")
    with open(GT_PATH,"w",encoding="utf-8") as f:
        json.dump(gt,f,indent=2,default=str)

    print(); print("="*60); print("  DATASET GENERATION COMPLETE"); print("="*60)
    print(f"  Total events  : {total:,}")
    print(f"  Attack events : {atk_lines:,}  ({atk_lines/total*100:.1f}%)")
    print(f"  Benign events : {ben_lines:,}  ({ben_lines/total*100:.1f}%)")
    print(f"  Malformed     : {n_mal:,}  (~2%)")
    print(f"  Campaigns     : {len(gt['attack_campaigns'])}")
    print(f"  Log file      : {SMALL_LOG_PATH}")
    print(f"  Ground truth  : {GT_PATH}")
    print("="*60)

if __name__=="__main__":
    main()

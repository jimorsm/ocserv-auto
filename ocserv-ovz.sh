#!/bin/bash

#密码设定
username="user"
password="password"
#端口设定
ssh_port=22
ac_port=20
ac_udp_port=5800

#ocserv安装
#版本设定
#ocserv版本
ocserv_version="0.10.9"
version=${1-${ocserv_version}}
libtasn1_version=4.7
# 安装源
yum install epel-release -y
# 安装iptables
yum install vim iptables-services -y
# 禁用firewalld
systemctl stop firewalld.service
systemctl disable firewalld.service
# 启用iptables
systemctl start iptables.service
systemctl enable iptables.service
# 安装依赖软件包
yum install -y gnutls gnutls-utils gnutls-devel readline readline-devel \
libnl-devel libtalloc libtalloc-devel libnl3-devel wget \
pam pam-devel libtalloc-devel xz libseccomp-devel \
tcp_wrappers-devel autogen autogen-libopts-devel tar \
gcc pcre-devel openssl openssl-devel curl-devel \
freeradius-client-devel freeradius-client lz4-devel lz4 \
http-parser-devel http-parser protobuf-c-devel protobuf-c \
pcllib-devel pcllib cyrus-sasl-gssapi dbus-devel policycoreutils gperf
#编译libtasn1
cd /usr/src
wget -t 0 -T 60 "http://ftp.gnu.org/gnu/libtasn1/libtasn1-${libtasn1_version}.tar.gz"
tar axf libtasn1-${libtasn1_version}.tar.gz
cd libtasn1-${libtasn1_version}
./configure --prefix=/usr --libdir=/usr/lib64 --includedir=/usr/include
make && make install
# 编译ocserv
cd /usr/src
wget -t 0 -T 60 "ftp://ftp.infradead.org/pub/ocserv/ocserv-${version}.tar.xz"
tar axf ocserv-${version}.tar.xz
cd ocserv-${version}
sed -i 's/#define MAX_CONFIG_ENTRIES.*/#define MAX_CONFIG_ENTRIES 200/g' src/vpn.h
./configure --prefix=/usr --sysconfdir=/etc
make && make install
# 复制配置文件
mkdir "/etc/ocserv"
cp "doc/sample.config" "/etc/ocserv/ocserv.conf"
cp "doc/systemd/standalone/ocserv.service" "/usr/lib/systemd/system/ocserv.service"
cp "doc/profile.xml" "/etc/ocserv/profile.xml"
# 创建证书
cd /root
certtool --generate-privkey --outfile ca-key.pem
cat << _EOF_ >ca.tmpl
cn = "puteulanus.com VPN"
organization = "puteulanus.com"
serial = 1
expiration_days = 3650
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_
certtool --generate-self-signed --load-privkey ca-key.pem \
--template ca.tmpl --outfile ca-cert.pem
certtool --generate-privkey --outfile server-key.pem
cat << _EOF_ >server.tmpl
cn = "puteulanus.com VPN"
organization = "puteulanus"
serial = 2
expiration_days = 3650
signing_key
encryption_key
tls_www_server
_EOF_
certtool --generate-certificate --load-privkey server-key.pem \
--load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
--template server.tmpl --outfile server-cert.pem
# 移动证书
mkdir -p /etc/ssl/{certs,private}
mv ca-cert.pem /etc/ssl/certs/
mv ca-key.pem /etc/ssl/private/
mv server-cert.pem /etc/ssl/certs/
mv server-key.pem /etc/ssl/private/
rm ca.tmpl server.tmpl -f
# 编辑配置文件
(echo "${password}"; sleep 1; echo "${password}") | ocpasswd -c "/etc/ocserv/ocpasswd" ${username}
sed -i "s#./sample.passwd#/etc/ocserv/ocpasswd#g" "/etc/ocserv/ocserv.conf"

sed -i "s#server-cert = ../tests/server-cert.pem#server-cert = /etc/ssl/certs/server-cert.pem#g" "/etc/ocserv/ocserv.conf"
sed -i "s#server-key = ../tests/server-key.pem#server-key = /etc/ssl/private/server-key.pem#g" "/etc/ocserv/ocserv.conf"
sed -i "s#ca-cert = ../tests/ca.pem#ca-cert = /etc/ssl/certs/ca-cert.pem#g" "/etc/ocserv/ocserv.conf"
sed -i 's/#enable-auth = "certificate"/enable-auth = "certificate"/g' "/etc/ocserv/ocserv.conf"
#sed -i "s/listen-clear-file = /#listen-clear-file = /g" "/etc/ocserv/ocserv.conf"

sed -i "s/max-same-clients = 2/max-same-clients = 8/g" "/etc/ocserv/ocserv.conf"
sed -i "s/max-clients = 16/max-clients = 32/g" "/etc/ocserv/ocserv.conf"

sed -i "s/tcp-port = 443/tcp-port = ${ac_port}/g" "/etc/ocserv/ocserv.conf"
sed -i "s/udp-port = 443/#udp-port = ${ac_udp_port}/g" "/etc/ocserv/ocserv.conf"

sed -i "s/default-domain = example.com/#default-domain = example.com/g" "/etc/ocserv/ocserv.conf"
sed -i "s/ipv4-network = 192.168.1.0/ipv4-network = 192.168.8.0/g" "/etc/ocserv/ocserv.conf"
sed -i "s/ipv4-netmask = 255.255.255.0/ipv4-netmask = 255.255.248.0/g" "/etc/ocserv/ocserv.conf"
sed -i "s/dns = 192.168.1.2/dns = 8.8.8.8\ndns = 8.8.4.4/g" "/etc/ocserv/ocserv.conf"
sed -i "s/run-as-group = daemon/run-as-group = nobody/g" "/etc/ocserv/ocserv.conf"
sed -i "s/cookie-timeout = 300/cookie-timeout = 86400/g" "/etc/ocserv/ocserv.conf"

sed -i 's$route = 10.10.10.0/255.255.255.0$#route = 10.10.10.0/255.255.255.0$g' "/etc/ocserv/ocserv.conf"
sed -i 's$route = 192.168.0.0/255.255.0.0$#route = 192.168.0.0/255.255.0.0$g' "/etc/ocserv/ocserv.conf"
sed -i 's$no-route = 192.168.5.0/255.255.255.0$#no-route = 192.168.5.0/255.255.255.0$g' "/etc/ocserv/ocserv.conf"

sed -i "s/isolate-workers = true/isolate-workers = false/g" "/etc/ocserv/ocserv.conf"

cat << _EOF_ >/usr/sbin/ocserv-client-cert
#! /bin/sh
#! /usr/bin/expect -f
certtool --generate-privkey --outfile \$1-key.pem
echo cn = "some random name" >client.tmpl
echo unit = "Puteulanus.com" >>client.tmpl
echo mail = "some random name" >>client.tmpl
echo uid = "`uuidgen`" >>client.tmpl
echo expiration_days = 365 >>client.tmpl
echo signing_key >>client.tmpl
echo tls_www_client >>client.tmpl
sed -i "1ccn = "\${1}"" client.tmpl
sed -i "3cemail = \${1}@abc.org" client.tmpl
certtool --generate-certificate --load-privkey \$1-key.pem --load-ca-certificate /etc/ssl/certs/ca-cert.pem --load-ca-privkey /etc/ssl/private/ca-key.pem --template client.tmpl --outfile \$1-cert.pem
openssl pkcs12 -export -inkey \$1-key.pem -in \$1-cert.pem -name "\$1 VPN Client Cert" -certfile /etc/ssl/certs/ca-cert.pem -out \$1.cert.p12
rm -f client.tmpl
exit 0
_EOF_
chmod +x /usr/sbin/ocserv-client-cert
# 路由表
#cat << _EOF_ >>/etc/ocserv/ocserv.conf
#route = 8.0.0.0/252.0.0.0
#route = 16.0.0.0/248.0.0.0
#route = 23.0.0.0/255.0.0.0
#route = 50.0.0.0/255.0.0.0
#route = 54.0.0.0/255.128.0.0
#route = 54.128.0.0/255.192.0.0
#route = 69.0.0.0/255.0.0.0
#route = 72.0.0.0/255.0.0.0
#route = 73.0.0.0/255.0.0.0
#route = 74.0.0.0/255.0.0.0
#route = 78.0.0.0/255.0.0.0
#route = 92.0.0.0/255.0.0.0
#route = 93.0.0.0/255.0.0.0
#route = 96.0.0.0/255.0.0.0
#route = 97.0.0.0/255.0.0.0
#route = 104.0.0.0/248.0.0.0
#route = 109.0.0.0/255.0.0.0
#route = 128.0.0.0/255.0.0.0
#route = 141.0.0.0/255.0.0.0
#route = 173.0.0.0/255.0.0.0
#route = 174.0.0.0/255.0.0.0
#route = 176.0.0.0/255.0.0.0
#route = 190.0.0.0/255.0.0.0
#route = 192.0.0.0/255.0.0.0
#route = 198.0.0.0/255.0.0.0
#route = 199.0.0.0/255.0.0.0
#route = 205.0.0.0/255.0.0.0
#route = 206.0.0.0/255.0.0.0
#route = 208.0.0.0/255.0.0.0
#route = 210.128.0.0/255.192.0.0
#route = 216.0.0.0/255.0.0.0
#route = 220.128.0.0/255.128.0.0
#_EOF_
# 打开转发
sysctl -w net.ipv4.ip_forward=1
echo net.ipv4.ip_forward = 1 >> "/etc/sysctl.conf"
sysctl -p
systemctl daemon-reload
# 设置iptables
cat << _EOF_ >/etc/sysconfig/iptables
*nat
-A POSTROUTING -j MASQUERADE
COMMIT
*filter
-A INPUT -i lo -j ACCEPT
-A INPUT -d 127.0.0.0/8 -j REJECT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -j ACCEPT
-A INPUT -p tcp -m tcp --dport ac_port -j ACCEPT
-A INPUT -p udp -m udp --dport ac_udp_port -j ACCEPT
-A INPUT -p tcp -m state --state NEW --dport ssh_port -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -m limit --limit 10/min -j LOG --log-prefix "iptables denied: " --log-level 7
-A INPUT -j DROP
-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
COMMIT
_EOF_

sed -i "s/--dport ac_port/--dport ${ac_port}/g" "/etc/sysconfig/iptables"
sed -i "s/--dport ac_udp_port/--dport ${ac_udp_port}/g" "/etc/sysconfig/iptables"
sed -i "s/--dport ssh_port/--dport ${ssh_port}/g" "/etc/sysconfig/iptables"

systemctl reload iptables.service
# 设置开机启动
systemctl enable ocserv.service
systemctl start ocserv.service
chmod +x "/etc/rc.d/rc.local"
echo systemctl restart ocserv.service >> "/etc/rc.d/rc.local"
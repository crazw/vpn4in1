vpn4in1
=======

Author：Crazw

E-mail:craazw@gmail.com

Blog:http://www.crazw.com/

=======

VPN4in1组件：

        pptp+openvpn(obfsproxy)+l2tp+shadowsocks

=======
安装方式：

        tar zxvf vpn4in1.tar.gz
      
        cd vpn4in1/
      
        sh vpn4in1.sh 2>&1 | tee vpn4in1.log

=======
笔记：
        1.安装日志：vpn4in1.log
        
        2.obfsproxy用于OpenVPN的流量混淆
        
        3.iptables路径：/etc/sysconfig/iptables
        
        4.obfsproxy的全局keys和server.conf放在/etc/openvpn目录下
        
        5.xl2tp【secret：zoa****.com user：echo passwd：110110】
        
        6. ShadowSocks的配置：/usr/local/conf/public.json文件
        	{
        	    "server":"0.0.0.0",
        	    "server_port":8888,
        	    "local_port":65500,
        	    "password":"110110",
        	    "timeout":600,
        	    "method":"table"
        	}
        	
        7.相关服务端口：ShadowSocks（TCP 8888）    Pptp（TCP 1723）     L2tp（TCP 1701 && UDP 1701）
                       Remote Desktop Services（TCP 3389）    SSH Remote Login Protocol（TCP 22） 
                       Ipsec（TCP 500）  Ipsec（UDP 4500）（仅供参考）
                       
        8.windows测试连接shadowsocks可以使用Freedbox.exe

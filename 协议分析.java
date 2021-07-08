import jpcap.PacketReceiver;
import jpcap.JpcapCaptor;
import jpcap.packet.*;
import jpcap.NetworkInterface;
import jpcap.NetworkInterfaceAddress;

public class 协议分析 implements PacketReceiver {

    public void receivePacket(Packet packet) {
        System.out.println("********************************************");
        byte[] l=packet.header;
        String str="";
        System.out.print("报文头 : ");
        for (int i=0;i<l.length;i++) {
            //str=str+l;
            int m=0;
            m=l[i];
            m=m<<24;
            m=m>>>24;
            str=str+Integer.toHexString(m);
        }
        System.out.println(str);
        int d=l.length;
        System.out.println("首部长度 ："+(d*8)+"bit");
        if(packet.getClass().equals(ARPPacket.class))
        {
            System.out.println("协议类型 ：ARP协议");
            try {
                ARPPacket arpPacket = (ARPPacket)packet;
                System.out.println("源网卡MAC地址为 ："+arpPacket.getSenderHardwareAddress());
                System.out.println("源IP地址为 ："+arpPacket.getSenderProtocolAddress());
                System.out.println("目的网卡MAC地址为 ："+arpPacket.getTargetHardwareAddress());
                System.out.println("目的IP地址为 ："+arpPacket.getTargetProtocolAddress());

            } catch( Exception e ) {
                e.printStackTrace();
            }
        }else if(packet.getClass().equals(IPPacket.class)) {
            System.out.println("协议类型 ：IP协议");
            try {
                IPPacket ipPacket = (IPPacket)packet;
                System.out.println("版本类型为 ："+ipPacket.version);
                System.out.println("总长度为 ："+ipPacket.length);
                System.out.println("片偏移为 ："+ipPacket.offset);
                System.out.println("协议为 ："+ipPacket.protocol);
                System.out.println("源IP地址为 ："+ipPacket.src_ip);
                System.out.println("目的IP地址为 ："+ipPacket.dst_ip);
            } catch( Exception e ) {
                e.printStackTrace();
            }
        } else if(packet.getClass().equals(UDPPacket.class))
        {
            System.out.println("协议类型 ：UDP协议");
            try {
                UDPPacket udpPacket = (UDPPacket)packet;
                System.out.println("源IP地址为 ："+udpPacket.src_ip);
                int tport = udpPacket.src_port;
                System.out.println("源端口为："+tport);
                System.out.println("目的IP地址为 ："+udpPacket.dst_ip);
                int lport = udpPacket.dst_port;
                System.out.println("目的端口为："+lport);
                System.out.println("长度为 ："+udpPacket.length);
            } catch( Exception e ) {
                e.printStackTrace();
            }
        } else if(packet.getClass().equals(TCPPacket.class)) {
            System.out.println("协议类型 ：TCP协议");
            try {
                TCPPacket tcpPacket = (TCPPacket)packet;
                int tport = tcpPacket.src_port;
                System.out.println("源IP地址为 ："+tcpPacket.src_ip);
                System.out.println("源端口为："+tport);
                System.out.println("目的IP地址为 ："+tcpPacket.dst_ip);
                int lport = tcpPacket.dst_port;
                System.out.println("目的端口为："+lport);
                System.out.println("数据偏移为："+tcpPacket.offset);
                System.out.println("序号为："+tcpPacket.sequence);
                System.out.println("确认序号为："+tcpPacket.ack_num);
                System.out.println("窗口为："+tcpPacket.window);
                System.out.println("SYN为："+tcpPacket.syn);
                System.out.println("FIN为："+tcpPacket.fin);
            } catch( Exception e ) {
                e.printStackTrace();
            }
        }
        else if(packet.getClass().equals(ICMPPacket.class))
            System.out.println("协议类型 ：ICMP协议");
        else
            System.out.println("协议类型 ：GGP、EGP、JGP协议或OSPF协议或ISO的第4类运输协议TP4");
        byte[] k=packet.data;
        String str1="";
        System.out.print("数据 : ");
        for(int i=0;i<k.length;i++) {
            str1 = new String(k);
        }
        System.out.println(str1);
        System.out.println("数据报类型 : "+packet.getClass());

        System.out.println("********************************************");
    }

    public static void main(String[] args) throws Exception{
        // TODO 自动生成方法存根
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        int a=0;
        byte[] b=devices[2].mac_address; //网卡物理地址
        System.out.print("网卡MAC : 00");
        for (int j=0;j<b.length;j++){
            a=b[j];
            a=a<<24;
            a=a>>>24;
            System.out.print(Integer.toHexString(a));
        }
        System.out.println();
        NetworkInterfaceAddress[] k=devices[2].addresses;
        for(int n=0;n<k.length;n++) {
            System.out.println("本机IP地址 : "+k[n].address);     //本机IP地址
            System.out.println("子网掩码   : "+k[n].subnet);      //子网掩码
        }
        System.out.println("网络连接类型 : "+devices[2].datalink_description);
        NetworkInterface deviceName = devices[2];
        /*将网卡设为混杂模式下用网络设备deviceName*/
        JpcapCaptor jpcap =JpcapCaptor.openDevice(deviceName, 2000, false, 1);
        jpcap.loopPacket(-1,new 协议分析());
    }
}

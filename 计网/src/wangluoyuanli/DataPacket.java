package wangluoyuanli;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import jpcap.packet.*;
import org.apache.commons.lang3.math.NumberUtils;//判断是否为数字
import jpcap.PacketReceiver;//使用Jpcap监听网卡，捕获数据包
public class DataPacket implements PacketReceiver {
    static int count = 0;
    static Map<Integer, ArpPacket> hmArp = new HashMap<Integer, ArpPacket>();
    //基于哈希表的map接口的实现和数组差不多，但是通过对象来对对象进行索引
    static Map<Integer, UdpPacket> hmUdp = new HashMap<Integer, UdpPacket>();
    static Map<Integer, IpPacket> hmIp = new HashMap<Integer, IpPacket>();
    static ArrayList<String> al = new ArrayList<String>();//定义了一个动态数组
    Main m = new Main();
    public void receivePacket(Packet packet) {//接收数据包

        if (packet.getClass().equals(ARPPacket.class)) {//如果接收的数据包为arp数据包
            count++;
            try {
                ARPPacket arp = (ARPPacket) packet;
                String target_ip = String.valueOf(arp.getTargetProtocolAddress());
                // 目的ip
                String target_mac = String.valueOf(arp.getTargetHardwareAddress());
                // 目的网卡地址
                String src_ip = String.valueOf(arp.getSenderProtocolAddress());
                // 本地ip
                String src_mac = String.valueOf(arp.getSenderHardwareAddress());
                // 本地网卡地址
                String len = arp.len + "";
                //创建一个arp对象
                ArpPacket ap = new ArpPacket(target_ip, target_mac, src_ip, src_mac, len);
                hmArp.put(count, ap);
                System.out.println(" id号:" + count);
                System.out.println(ap.toString());
                al.add(ap.toString());//把它写入文件中
            } catch (Exception e) {
                e.printStackTrace();//打印异常信息
            }
        } else if (packet.getClass().equals(UDPPacket.class)) {
            count++;
            try {
                UDPPacket udp = (UDPPacket) packet;
                String dst_ip = String.valueOf(udp.dst_ip);
                String dst_port = String.valueOf(udp.dst_port);
                String src_ip = String.valueOf(udp.src_ip);
                String src_port = String.valueOf(udp.src_port);
                String len = udp.len + "";
                UdpPacket up = new UdpPacket(dst_ip, dst_port, src_ip, src_port, len);
                hmUdp.put(count, up);
                System.out.println(" id号:" + count);
                System.out.println(up.toString());
                System.out.println();
                al.add(up.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (packet.getClass().equals(IPPacket.class)) {
            count++;
            try {
                IPPacket ip = (IPPacket) packet;
                String version =String.valueOf(ip.version);//版本号
                String len=String.valueOf(ip.len);
                String length=String.valueOf(ip.length);//长度
                String ident =String.valueOf(ip.ident);//标识
                String r_flag=String.valueOf(ip.r_flag);//标志
                String offset=String.valueOf(ip.offset);//片偏移
                String protocol=String.valueOf(ip.protocol);//协议
                String dst_ip=String.valueOf(ip.dst_ip);
                String src_ip=String.valueOf(ip.src_ip);//本地ip
                IpPacket IP = new IpPacket( version,  len,  length,  ident,  r_flag,  offset,  protocol,  dst_ip,  src_ip);
                hmIp.put(count, IP);
                System.out.println(" id号:" + count);
                System.out.println( IP.toString());
                System.out.println();
                al.add(IP.toString());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else{
            count++;
            System.out.println("Other:" + count);
            System.out.println("协议类型 ：ICMP、GGP、EGP、JGP协议或OSPF协议或ISO的第4类运输协议TP4");
            System.out.println();
        }
    }
    public void search() {
        System.out.println(
                "输入数字查看此次捕捉的协议包" + "\n" + "1. arp" + "\n" + "" + "2. tcp" + "\n" + "3. udp" + "\n" + "4. 返回重新捕捉协议包");
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        if (st.equals("1")) {
            arpWatch();
            // search();
        } else if (st.equals("2")) {
            ipWatch();
            // search();
        } else if (st.equals("3")) {
            udpWatch();
            // search();
        } else if (st.equals("4")) {
            // m.capture();
        }
        else {
            System.out.println("输入错误，请重新输入");
            search();
        }

    }
    public void arpWatch() {
        System.out.println();
        System.out.println("arp协议包一共有" + hmArp.size() + "个" + "\n" + "输入0:显示 本次 协议包的详细信息," + "\n"
                + "输入协议包的id号，查看此包的详细信息" + "\n" + "输入.  查看其它类型协议包");
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        if (hmArp.size() == 0) {
            System.out.println("第" + m.captureCount + "次捕捉不存在Arp协议数据包");
            search();
        } else if (st.equals("0")) {
            System.out.println("第" + m.captureCount + "次捕捉Arp协议数据包详细信息如下:" + "\n");
            for (int i = 1+(m.captureCount-1)*100 ; i <= m.captureCount * 100; i++) {
                if (hmArp.get(i) == null) {

                } else {
                    System.out.println(i + "--->" + hmArp.get(i));
                }
            }
            arpWatch();
        } else if (NumberUtils.isDigits(st)) {//如果是id号
            if (Integer.parseInt(st) > (m.captureCount-1)*100&& Integer.parseInt(st) <= m.captureCount * 100) {
                if (hmArp.get(Integer.parseInt(st)) != null) {
                    System.out.println(st + "--->" + hmArp.get(Integer.parseInt(st)));
                } else {
                    System.out.println("此id包不是arp协议包，");
                }
                arpWatch();
            } else {
                System.out.println("id号范围输入错误，请重新输入");
                arpWatch();
            }
        } else if (st.equals("."+".")) {
            m.startCapture();
        } else if (st.equals(".")) {
            search();
        } else {
            System.out.println("输入错误，请重新输入");
            arpWatch();
        }
    }
    public void ipWatch() {
        System.out.println();
        System.out.println("ip协议包一共有" + hmIp.size() + "个" + "\n"+"输入0:显示 本次 协议包的详细信息," + "\n"
                + "输入协议包的id号，查看此包的详细信息" + "\n" + "输入. 查看其它类型协议包" );
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        if (hmIp.size() == 0) {
            System.out.println("第" + m.captureCount + "次捕捉不存在TCP协议数据包");
            search();
        } else if (st.equals("0")) {
            System.out.println("第" + m.captureCount + "次捕捉TCP协议数据包详细信息如下:" + "\n");
            for (int i = 1 + (m.captureCount - 1) * 100; i <= m.captureCount * 100; i++) {
                if (hmIp.get(i) == null) {
                } else {
                    System.out.println(i + "--->" + hmIp.get(i));
                }
            }
            ipWatch();
        } else if (NumberUtils.isNumber(st)) {
            if (Integer.parseInt(st) >(m.captureCount - 1) * 100 && Integer.parseInt(st) <= m.captureCount * 10) {
                if (hmIp.get(Integer.parseInt(st)) != null) {
                    System.out.println(st + "--->" + hmIp.get(Integer.parseInt(st)));

                } else {
                    System.out.println("此id包不是tcp协议包，");
                }
                ipWatch();
            } else {
                System.out.println("id号范围输入错误，请重新输入");
                ipWatch();
            }
        } else if (st.equals("..")) {
            m.startCapture();
        } else if (st.equals(".")) {
            search();
        } else {
            System.out.println("输入错误，请重新输入");
            ipWatch();
        }
    }
    public void udpWatch() {
        System.out.println();
        System.out.println("udp协议包一共有" + hmUdp.size() + "个" + "\n" + "输入0:显示 本次 协议包的详细信息," + "\n"
                + "输入协议包的id号，查看此包的详细信息" + "\n" + "输入.  查看其它类型协议包" );
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        if (hmUdp.size() == 0) {
            System.out.println("第" + m.captureCount + "次捕捉不存在UDP协议数据包");
            search();
        } else if (st.equals("0")) {
            System.out.println("第" + m.captureCount + "次捕捉udp协议数据包详细信息如下:" + "\n");
            for (int i = 1 + (m.captureCount - 1) * 100; i <= m.captureCount * 100; i++) {
                if (hmUdp.get(i) == null) {
                } else {
                    System.out.println(i + "--->" + hmUdp.get(i));
                }
            }
            udpWatch();
        } else if (NumberUtils.isNumber(st)) {
            if (Integer.parseInt(st) >(m.captureCount - 1) * 100&& Integer.parseInt(st) <= m.captureCount * 10) {
                if (hmUdp.get(Integer.parseInt(st)) != null) {
                    System.out.println(st + "--->" + hmUdp.get(Integer.parseInt(st)));

                } else {
                    System.out.println("此id包不是udp协议包，");
                }
                udpWatch();
            } else {
                System.out.println("id号范围输入错误，请重新输入");
                udpWatch();
            }
        } else if (st.equals("..")) {
            m.startCapture();
        } else if (st.equals(".")) {
            search();
        } else {
            System.out.println("输入错误，请重新输入");
            udpWatch();
        }
    }
    public String write() {// 写入本地
        String path = null;
        try {
            Date d = new Date();
            SimpleDateFormat dateF = new SimpleDateFormat("yyyy-MM-dd_HH-mm-ss");
//SimpleDateFormat是java.text包下的类，设置时间格式
            String s = dateF.format(d.getTime());//获取本机的时间
            path = "F:\\test.txt";
            FileOutputStream fis = new FileOutputStream(path, true);//文件写入的路径
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(fis));//缓冲输入流
            for (int i = 0; i < al.size(); i++) {
                writer.write(i + 1 + "-->" + al.get(i) + "\n");//将数据写入缓冲区中
            }
            writer.flush();//刷新缓冲输入流，将内容写入文件中
            writer.close();//关闭文件
        } catch (Exception e) {
            e.printStackTrace();
        }
        return path;
    }
    public void delFile(String path) {
        try {
            File myDelFile = new File(path);
            myDelFile.delete();
            //System.out.println("删除文件操作成功执行");
        } catch (Exception e) {
            System.out.println("删除文件操作出错");
            e.printStackTrace();
        }
    }
}

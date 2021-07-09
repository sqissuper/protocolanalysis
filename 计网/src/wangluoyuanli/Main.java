package wangluoyuanli;

import java.io.IOException;
import java.util.Scanner;
import jpcap.*;
public class Main {
    static JpcapCaptor jpcap = null;
    static jpcap.NetworkInterface[] devices = JpcapCaptor.getDeviceList();
    static DataPacket dp = new DataPacket();
    static int captureCount;// 记录捕捉的次数
    static String path = null;
    public static void main(String[] args) {
        if(devices.length==0){
            System.out.println("无网卡信息");
            return;
        }
        //输出网卡信息
        for (int i = 0; i < devices.length; i++) {
            System.out.println("网卡"+i+"  信息"+devices[i].name);
            for (NetworkInterfaceAddress address : devices[i].addresses) {
                System.out.print(address.address+" ");
            }
            System.out.println("\n");
        }
        // 返回机器上网络接口卡对象的数组
        int a = 0;
        byte[] b = devices[4].mac_address; // 网卡物理地址
        System.out.println("------------------本机网卡信息-----------------------");
        System.out.println("网卡名称 : " + devices[4].name);
        System.out.print("网卡地址:");
        for (int j = 0; j < b.length; j++) {
            a = b[j];
            a = a << 24;
            a = a >>> 24;
            System.out.print(Integer.toHexString(a));
        }
        System.out.println();
        int netLine = 1;
        NetworkInterfaceAddress[] k = devices[1].addresses;
         for (int n = 0; n < k.length; n++) {
        System.out.println("本机IP地址 : " + k[netLine].address); // 本机IP地址
        System.out.println("子网掩码   : " + k[netLine].subnet); // 子网掩码
         }
        System.out.println("网络连接类型 : " + devices[netLine].datalink_description);
        System.out.println(
                "网卡类型：" + devices[netLine].description + "\n" + "网络设备所对应数据链路层的名称 " + devices[netLine].datalink_name);
        // 以太网（Ethernet）、无线LAN网（wireless LAN）、令牌环网(token ring)
        startCapture();
    }
    //开始捕捉数据包
    static void startCapture() {
        //Packet packet=jpcap.getPacket();
        NetworkInterface deviceName = devices[4];
        /* 将网卡设为混杂模式下用网络设备deviceName */
        try {
            jpcap = JpcapCaptor.openDevice(deviceName, 20000, false, 1);
            capture();// 选择捕捉类型
        } catch (Exception e) {
        }
    }
    static void capture() {
        captureCount++;//
        System.out.println("\n" + "请选择捕捉协议类型:");
        System.out.println("0:全部协议类型" + "\n" + "1. arp" + "\n" + "" + "2. ip " + "\n" + "3. udp" + "\n" + "4. 准备结束操作");
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        try {
            if (st.equals("0")) {
                loop(st);
            } else if (st.equals("1")) {
                jpcap.setFilter("arp", true);// 需要捕捉异常
                loop(st);
            } else if (st.equals("2")) {
                jpcap.setFilter("ip", true);
                loop(st);
            } else if (st.equals("3")) {
                jpcap.setFilter("udp", true);
                loop(st);
            } else if (st.equals("4")) {
                isExist();
            } else {
                System.out.println("输入错误，请重新输入");
                capture();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    static void loop(String st) {// 开始捕捉数据包
        System.out.println("请稍等……" + "\n");
        new Thread(()->{
            jpcap.loopPacket(-1, new DataPacket());
        }).start();
        // 连续地捕获数据包，返回捕获数据包的数量。 参数count是要捕获数据包的数量，可以将其设置为-1， 这样就可以持续抓包直到EOF或发生错误为止。
        path = dp.write();// 写入本地文件
        if (st.equals("0")) {
            dp.search();
        } else if (st.equals("1")) {
            dp.arpWatch();
        } else if (st.equals("2")) {
            dp.ipWatch();
        } else if (st.equals("3")) {
            dp.udpWatch();
        }
        startCapture();
    }



    public static void isExist() {
        if (captureCount == 1) {
            System.out.println("退出成功");
            System.exit(0);
        }
        System.out.println("是否在本地保存此次捕捉协议包数据" + "\n" + "0:保存" + "\n" + "1:不保存");
        Scanner sc = new Scanner(System.in);
        String st = sc.nextLine();
        if (st.equals("0")) {
            System.out.println("保存文件成功");
            System.out.println("退出成功");
            System.exit(0);
        } else if (st.equals("1")) {
            dp.delFile(path);// 删除文件的方法
            System.out.println("退出成功");
            System.exit(0);
        } else {
            System.out.println("输入错误，重新输入");
            isExist();
        }
    }
}

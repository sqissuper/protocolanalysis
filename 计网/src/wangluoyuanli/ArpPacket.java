package wangluoyuanli;

public class ArpPacket {
    String dst_ip;
    String dst_port;
    String src_ip;
    String src_port;
    String len;
    public ArpPacket(String dst_ip, String dst_port, String src_ip, String src_port, String len) {
        super();
        this.dst_ip = dst_ip;
        this.dst_port = dst_port;
        this.src_ip = src_ip;
        this.src_port = src_port;
        this.len = len;
    }
    public String getDst_ip() {
        return dst_ip;
    }
    public void setDst_ip(String dst_ip) {
        this.dst_ip = dst_ip;
    }
    public String getDst_port() {
        return dst_port;
    }
    public void setDst_port(String dst_port) {
        this.dst_port = dst_port;
    }
    public String getSrc_ip() {
        return src_ip;
    }
    public void setSrc_ip(String src_ip) {
        this.src_ip = src_ip;
    }

    public String getSrc_port() {
        return src_port;
    }
    public void setSrc_port(String src_port) {
        this.src_port = src_port;
    }
    public String getLen() {
        return len;
    }
    public void setLen(String len) {
        this.len = len;
    }
    public String toString() {
        return ("ArpPacket [目标ip" + dst_ip + ", 目标网卡地址=" + dst_port + ", 本地ip=" + src_ip + ", 本地网卡地址="
                + src_port + ", 长度len=" + len + "]");
    }
}

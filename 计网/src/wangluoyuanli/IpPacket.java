package wangluoyuanli;

public class IpPacket {
    String version ;//版本号
    String len;
    String length;//长度
    String ident ;//标识
    String r_flag;//标志
    String offset;//片偏移
    String protocol;//协议
    String dst_ip;
    String src_ip;

    public IpPacket() {
    }
    public IpPacket(String version, String len, String length, String ident, String r_flag, String offset, String protocol, String dst_ip, String src_ip) {
        this.version = version;
        this.len = len;
        this.length = length;
        this.ident = ident;
        this.r_flag = r_flag;
        this.offset = offset;
        this.protocol = protocol;
        this.dst_ip = dst_ip;
        this.src_ip = src_ip;
    }
    public String getVersion() {
        return version;
    }
    public void setVersion(String version) {
        this.version = version;
    }
    public String getLen() {
        return len;
    }
    public void setLen(String len) {
        this.len = len;
    }
    public String getLength() {
        return length;
    }

    public void setLength(String length) {
        this.length = length;
    }
    public String getIdent() {
        return ident;
    }
    public void setIdent(String ident) {
        this.ident = ident;
    }
    public String getR_flag() {
        return r_flag;
    }
    public void setR_flag(String r_flag) {
        this.r_flag = r_flag;
    }
    public String getOffset() {
        return offset;
    }
    public void setOffset(String offset) {
        this.offset = offset;
    }
    public String getProtocol() {
        return protocol;
    }
    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }
    public String getDst_ip() {
        return dst_ip;
    }
    public void setDst_ip(String dst_ip) {
        this.dst_ip = dst_ip;
    }
    public String getSrc_ip() {
        return src_ip;
    }
    public void setSrc_ip(String src_ip) {
        this.src_ip = src_ip;
    }
    public String toString() {
        return ("IpPacket:[版本号:" + version + ", 总长度:" + len + ", 首部长度:" + length + ", 标识:"
                + ident + ", 标志=" + r_flag +  "\n" +" 片偏移:" + offset + ", 协议:" + protocol + ", 源地址:" + src_ip
                + ", 目标地址:" + dst_ip +  "]");

    }
}

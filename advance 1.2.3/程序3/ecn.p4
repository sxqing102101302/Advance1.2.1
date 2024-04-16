/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  TCP_PROTOCOL = 0x06; //TCP协议
const bit<16> TYPE_IPV4 = 0x800; //IPV4协议类型

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;  // 定义egressSpec_t为9位的数据类型
typedef bit<48> macAddr_t;     // 定义macAddr_t为48位的数据类型
typedef bit<32> ip4Addr_t;      // 定义ip4Addr_t为32位的数据类型

header ethernet_t {  // 定义名为ethernet_t的头部结构
    macAddr_t dstAddr;  // 目的MAC地址字段
    macAddr_t srcAddr;  // 源MAC地址字段
    bit<16>   etherType;  // 以太网类型字段
}

header ipv4_t {  // 定义名为ipv4_t的头部结构
    bit<4>    version;  // IPv4版本字段
    bit<4>    ihl;  // 头部长度字段
    bit<6>    diffserv;  // 区分服务字段
    bit<2>    ecn;  // 显式拥塞通告(ECN)字段
    bit<16>   totalLen;  // 总长度字段
    bit<16>   identification;  // 标识字段
    bit<3>    flags;  // 标志字段
    bit<13>   fragOffset;  // 分段偏移字段
    bit<8>    ttl;  // 存活时间字段
    bit<8>    protocol;  // 协议字段
    bit<16>   hdrChecksum;  // 头部校验和字段
    ip4Addr_t srcAddr;  // 源IPv4地址字段
    ip4Addr_t dstAddr;  // 目的IPv4地址字段
}

struct metadata {  // 定义名为metadata的元数据结构
    bit<19> ecn_threshold;
}

struct headers {  // 定义名为headers的头部结构
    ethernet_t   ethernet;  // 以太网头部
    ipv4_t       ipv4;  // IPv4头部
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {  // 定义名为start的状态
        transition parse_ethernet;  // 转移到parse_ethernet状态
    }

    state parse_ethernet {  // 定义名为parse_ethernet的状态
        packet.extract(hdr.ethernet);  // 提取以太网头部
        transition select(hdr.ethernet.etherType) {  // 根据以太网类型选择转移
            TYPE_IPV4: parse_ipv4;  // 如果是IPv4类型，则转移到parse_ipv4状态
            default: accept;  // 否则接受数据包
        }
    }

    state parse_ipv4 {  // 定义名为parse_ipv4的状态
        packet.extract(hdr.ipv4);  // 提取IPv4头部
        transition accept;  // 接受数据包
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }  // 应用空操作
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {  // 定义名为drop的动作
        mark_to_drop(standard_metadata);  // 标记丢弃数据包
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {  // 定义名为ipv4_forward的动作，传入目的MAC地址和出口端口
        standard_metadata.egress_spec = port;  // 设置出口端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;  // 设置以太网源MAC地址为目的MAC地址
        hdr.ethernet.dstAddr = dstAddr;  // 设置以太网目的MAC地址为传入的目的MAC地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;  // 减少IPv4数据包的TTL值
    }

    table ipv4_lpm {  // 定义名为ipv4_lpm的表
        key = {  // 键定义
            hdr.ipv4.dstAddr: lpm;  // 使用IPv4目的地址进行最长前缀匹配
        }
        actions = {  // 动作集合
            ipv4_forward;  // 调用ipv4_forward动作
            drop;  // 调用drop动作
            NoAction;  // 无操作
        }
        size = 1024;  // 表大小
        default_action = NoAction();  // 默认动作为无操作
    }

    apply {  // 应用
        if (hdr.ipv4.isValid()) {  // 如果IPv4头部有效
            ipv4_lpm.apply();  // 应用ipv4_lpm表
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action mark_ecn_threshold(bit<19> ecn_threshold) {
        meta.ecn_threshold = ecn_threshold;
    }

    table ecn_threshold_set {
        key = {}
        actions = {
            mark_ecn_threshold;
        }
    }

    action report_congestion(bit<32> session) {
        // 调用clone_preserving_field_list来克隆数据包并发送到控制平面
        clone_preserving_field_list(CloneType.E2E, session, 0);
    }

    // 应用部分
    apply {
        ecn_threshold_set.apply();
        // 如果 IPv4 头部的 ECN 字段为1或2
        if (hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){
            // 如果输入队列深度大于等于ECN阈值
            if (standard_metadata.enq_qdepth >= meta.ecn_threshold){
                hdr.ipv4.ecn = 3;
            }
        }
        // 如果ECN值为3，报告拥塞情况
        if (hdr.ipv4.ecn == 3) {
            report_congestion(100); // 假设session id为100
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {  // 应用
        update_checksum(  // 更新校验和
            hdr.ipv4.isValid(),  // 检查IPv4头部是否有效
            { hdr.ipv4.version,  // 版本字段
              hdr.ipv4.ihl,  // 头部长度字段
              hdr.ipv4.diffserv,  // 区分服务字段
              hdr.ipv4.ecn,  // ECN字段
              hdr.ipv4.totalLen,  // 总长度字段
              hdr.ipv4.identification,  // 标识字段
              hdr.ipv4.flags,  // 标志字段
              hdr.ipv4.fragOffset,  // 分段偏移字段
              hdr.ipv4.ttl,  // TTL字段
              hdr.ipv4.protocol,  // 协议字段
              hdr.ipv4.srcAddr,  // 源IPv4地址字段
              hdr.ipv4.dstAddr },  // 目的IPv4地址字段
            hdr.ipv4.hdrChecksum,  // IPv4头部校验和字段
            HashAlgorithm.csum16);  // 使用csum16哈希算法
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {  // 应用
        packet.emit(hdr.ethernet);  // 发射以太网头部
        packet.emit(hdr.ipv4);  // 发射IPv4头部
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(  // 定义V1交换机
MyParser(),  // 解析器模块
MyVerifyChecksum(),  // 校验和验证模块
MyIngress(),  // Ingress处理模块
MyEgress(),  // Egress处理模块
MyComputeChecksum(),  // 计算校验和模块
MyDeparser()  // 解析器模块
) main;  // 主模块

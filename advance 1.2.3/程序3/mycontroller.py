#!/usr/bin/env python3

# 导入必要的库和模块
import argparse  # 用于解析命令行参数
import os
import sys
from time import sleep
import threading
import logging
import grpc  # gRPC通信库

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2  # P4Runtime BMv2交互库
import p4runtime_lib.helper  # P4Runtime辅助函数
from p4runtime_lib.switch import ShutdownAllSwitchConnections  # 关闭所有交换机连接
# 设置日志记录器
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def buildCloneSessionEntry(p4info_helper, clone_session_id, replicas):
    """
    构造克隆会话表项
    """
    # ... 现有代码 ...
    # 添加一个端口，用于发送到控制平面
    cpu_port=252
    replicas.append({"egress_port": cpu_port, "instance": 3})
    return p4info_helper.buildCloneSessionEntry(clone_session_id, replicas)

def parse_ipv4(packet_data):
    # IPv4头部的偏移量（以太网头部长度为14字节）
    ipv4_offset = 14 # IPv4头部的长度（单位：字节）
    # ipv4_header_length = (packet_data[ipv4_offset] & 0x0F) * 4
    
    # ECN字段在IPv4头部中的偏移量
    ecn_offset = ipv4_offset + 1 # ECN字段在IPv4头部的第二个字节

    # 从数据包字节流中读取ECN字段的值
    ecn_value = (packet_data[ecn_offset] & 0b11000000) >> 6 # 获取前两位表示ECN的值

    return ecn_value

# 在 handle_packet 函数中调用 parse_ipv4 函数解析数据包
def handle_packet(connection):
    try:
        for response in connection.stream_msg_resp:
            if response.WhichOneof("update") == "packet":
                # 假设 response.packet 是一个包含原始数据包字节的字节串
                packet_data = response.packet.payload
                # 解析 IPv4 头部并获取 ECN 值
                ecn = parse_ipv4(packet_data)
                # 根据 ECN 值进行逻辑处理
                if ecn == 3:
                    print("Receive response -----\nECN value:3\nCongestion happens!!\n")
                elif ecn == 1:
                    print("Receive response -----\nECN value:1\n")
                elif ecn == 2:
                    print("Receive response -----\nECN value:2\n")
    except AttributeError as e:
        print("AttributeError:", e)
    except grpc.RpcError as e:
        printGrpcError(e)


def writeIpv4ForwardRules(p4info_helper, ingress_sw, egress_sw, match_fields,
                          dstaddr, port):
    """
    写入IPv4转发规则到交换机

    Args:
        p4info_helper: P4InfoHelper对象，用于构建表项
        ingress_sw: 输入交换机对象
        egress_sw: 输出交换机对象
        match_fields: 匹配字段
        dstaddr: 目标地址
        port: 端口号
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": match_fields
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dstaddr,
            "port": port
        })
    ingress_sw.WriteTableEntry(table_entry)
    print("Installed ingress ipv4forward rule on %s" % ingress_sw.name)


def writeECNThreshold(p4info_helper, sw, threshold):
    """
    写入ECN阈值到交换机的特殊表中

    Args:
        p4info_helper: P4InfoHelper对象，用于构建表项
        sw: 交换机对象
        threshold: ECN阈值
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.ecn_threshold_set",
        action_name="MyEgress.mark_ecn_threshold",
        action_params={
            "ecn_threshold": threshold,
        })
    sw.WriteTableEntry(table_entry)
    print("Installed ECN threshold rule on %s" % sw.name)


def printGrpcError(e):
    """
    打印gRPC错误信息

    Args:
        e: gRPC错误对象
    """
    print("gRPC Error:", e.details(), end=' ')
    status_code = e.code()
    print("(%s)" % status_code.name, end=' ')
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


def main(p4info_file_path, bmv2_file_path):
    """
    主函数，连接到交换机并安装P4程序和流表规则

    Args:
        p4info_file_path: P4Info文件路径
        bmv2_file_path: BMv2 JSON文件路径
    """
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        # 连接到三个BMv2交换机
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # 更新主节点的状态信息
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # 用户自定义ECN阈值
        threshold = int(input("Please input the threshold of the queue: "))

        # 在交换机上安装P4程序
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        # s1的流规则
        writeECNThreshold(p4info_helper, s1, threshold)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,match_fields= ["10.0.1.1", 32],dstaddr="08:00:00:00:01:01",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,match_fields= ["10.0.1.11", 32],dstaddr="08:00:00:00:01:11",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s2,match_fields= ["10.0.2.0", 24],dstaddr="08:00:00:00:02:00",port=3)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s3,match_fields= ["10.0.3.0", 24],dstaddr="08:00:00:00:03:00",port=4)

        #s2的流规则
        writeECNThreshold(p4info_helper, s2, threshold)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,match_fields= ["10.0.2.2", 32],dstaddr="08:00:00:00:02:02",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,match_fields=["10.0.2.22", 32],dstaddr="08:00:00:00:02:22",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s1,match_fields= ["10.0.1.0", 24],dstaddr="08:00:00:00:01:00",port=3)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s3,match_fields=["10.0.3.0", 24],dstaddr="08:00:00:00:03:00",port=4)


         #s3的流规则
        writeECNThreshold(p4info_helper, s3, threshold)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s3,match_fields=["10.0.3.3", 32],dstaddr="08:00:00:00:03:03",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s1,match_fields=["10.0.1.0", 24],dstaddr="08:00:00:00:01:00",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s2,match_fields=["10.0.2.0", 24],dstaddr="08:00:00:00:02:00",port=3)

        # 创建克隆会话表项并下发到交换机
        print("\nMonitoring network congestion ...")
        clone_session_id = 100  # 假设会话ID为100
        replicas = [
            {"egress_port": 2, "instance": 1},  # 假设控制平面端口为2
            {"egress_port": 252, "instance": 2}  # 假设CPU端口为252
        ]
        entry = buildCloneSessionEntry(p4info_helper, clone_session_id, replicas)
        s1.WritePREEntry(entry)

        handle_packet(s1)
        # thread = threading.Thread(target=handle_packet, args=(s1, 3))
        # thread.start()

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    # 关闭所有交换机连接
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)

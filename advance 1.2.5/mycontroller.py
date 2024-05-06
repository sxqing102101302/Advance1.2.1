#!/usr/bin/env python3

# 导入必要的库和模块
import argparse  # 用于解析命令行参数
import os
import sys
from time import sleep

import grpc  # gRPC通信库

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2  # P4Runtime BMv2交互库
import p4runtime_lib.helper  # P4Runtime辅助函数
from p4runtime_lib.switch import ShutdownAllSwitchConnections  # 关闭所有交换机连接

def writeIpv4ForwardDefault(p4info_helper, sw):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        default_action=True,
        action_name="MyIngress.drop",
        action_params={})
    sw.WriteTableEntry(table_entry)
    print("Installed default drop action on 'MyIngress.ipv4_lpm'")

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

def writeSwidRules(p4info_helper, egress_sw, swid):
    """
    设置MyEgress.swid表的默认行为

    Args:
        p4info_helper: P4InfoHelper对象，用于构建表项
        egress_sw: 输出交换机对象
        swid: 交换机ID
    """
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swid",
        default_action=True,
        action_name="MyEgress.set_swid",
        action_params={
            "swid": swid
        })
    egress_sw.WriteTableEntry(table_entry)
    print("Installed egress swid rule on %s" % egress_sw.name)

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
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        # 更新主节点的状态信息
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

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
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s4")
        
        writeIpv4ForwardDefault(p4info_helper, s1)
        writeIpv4ForwardDefault(p4info_helper, s2)
        writeIpv4ForwardDefault(p4info_helper, s3)
        writeIpv4ForwardDefault(p4info_helper, s4)

        # s1的流规则
        writeSwidRules(p4info_helper, egress_sw=s1, swid=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,match_fields=["10.0.1.1", 32],dstaddr="08:00:00:00:01:11",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,match_fields=["10.0.2.2", 32],dstaddr="08:00:00:00:02:22",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s3,match_fields=["10.0.3.3", 32],dstaddr="08:00:00:00:03:00",port=3)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s4,match_fields=["10.0.4.4", 32],dstaddr="08:00:00:00:04:00",port=4)

        #s2的流规则
        writeSwidRules(p4info_helper, egress_sw=s2, swid=2)       
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s3,match_fields=["10.0.1.1", 32],dstaddr="08:00:00:00:03:00",port=4)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s4,match_fields=["10.0.2.2", 32],dstaddr="08:00:00:00:04:00",port=3)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,match_fields=["10.0.3.3", 32],dstaddr="08:00:00:00:03:33",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s3,match_fields=["10.0.4.4", 32],dstaddr="08:00:00:00:04:44",port=2)


         #s3的流规则           
        writeSwidRules(p4info_helper, egress_sw=s3, swid=3)   
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s1,match_fields=["10.0.1.1", 32],dstaddr="08:00:00:00:01:00",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s1,match_fields=["10.0.2.2", 32],dstaddr="08:00:00:00:01:00",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s2,match_fields=["10.0.3.3", 32],dstaddr="08:00:00:00:02:00",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s1,match_fields=["10.0.4.4", 32],dstaddr="08:00:00:00:02:00",port=2)

        
        #s4的流规则
        writeSwidRules(p4info_helper, egress_sw=s4, swid=4) 
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s4, egress_sw=s1,match_fields=["10.0.1.1", 32],dstaddr="08:00:00:00:01:00",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s4, egress_sw=s1,match_fields=["10.0.2.2", 32],dstaddr="08:00:00:00:01:00",port=2)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s4, egress_sw=s2,match_fields=["10.0.3.3", 32],dstaddr="08:00:00:00:02:00",port=1)
        writeIpv4ForwardRules(p4info_helper, ingress_sw=s4, egress_sw=s2,match_fields=["10.0.4.4", 32],dstaddr="08:00:00:00:02:00",port=1)

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
                        default='./build/link_monitor.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/link_monitor.json')
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
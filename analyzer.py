# analyzer.py
import dpkt
import socket
from collections import defaultdict
import os
import queue
import traceback
import time # Import time for potential duration calculation

def analyze_pcap(file_path, result_queue, top_n=10):
    """
    在后台线程中分析 PCAP 文件。
    :param file_path: pcap 文件路径
    :param result_queue: 用于将结果或错误发送回主线程的队列
    :param top_n: 显示 Top N 的 IP 地址数量
    """
    start_time = time.time() # 记录开始时间
    try:
        source_ips = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        dest_ips = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        protocols = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        total_packets = 0
        total_bytes = 0
        processed_bytes = 0 # 用于计算进度

        try:
            # 获取文件总大小用于计算进度
            # 注意：对于非常大的文件 (>几GB)，一次性读取可能导致内存问题
            # 更健壮的方法可能需要分块读取或不同的进度估算策略
            file_size = os.path.getsize(file_path)
        except OSError:
            file_size = 0 # 如果无法获取大小，则无法显示精确进度

        with open(file_path, 'rb') as f:
            # 尝试确定文件类型 (pcap 或 pcapng) - dpkt Reader 会自动处理
            try:
                # 使用 BytesIO 方便计算进度，但会将整个文件读入内存
                # 对于非常大的文件，这可能不是最佳选择
                buffered_f = dpkt.compat.BytesIO(f.read())
                pcap = dpkt.pcap.Reader(buffered_f)
            except ValueError as e:
                 # 可能是 pcapng, 尝试 dpkt.pcapng.Reader
                 buffered_f.seek(0) # 重置 BytesIO 指针
                 try:
                     pcap = dpkt.pcapng.Reader(buffered_f)
                 except Exception as e_ng:
                     # 如果 pcapng 也失败，可能文件格式确实不支持或已损坏
                     raise ValueError(f"无法识别的 PCAP/PCAPNG 文件格式: {e}, {e_ng}")


            last_progress_update_percent = 0 # 记录上次更新进度的百分比整数部分
            update_interval_percent = 1 # 每增加 1% 更新一次

            for timestamp, buf in pcap:
                total_packets += 1
                packet_len = len(buf)
                total_bytes += packet_len
                processed_bytes += packet_len # 累加处理的字节数

                # --- 计算并发送进度 ---
                if file_size > 0:
                    current_progress_percent = int((processed_bytes / file_size) * 100)
                    # 仅当进度变化达到阈值时才发送更新，避免过于频繁
                    if current_progress_percent >= last_progress_update_percent + update_interval_percent:
                        result_queue.put({'status': 'progress', 'data': processed_bytes / file_size})
                        last_progress_update_percent = current_progress_percent
                # --- 结束进度计算 ---

                try:
                    # 解析以太网帧
                    eth = dpkt.ethernet.Ethernet(buf)

                    # 确保是 IP 包
                    if not isinstance(eth.data, dpkt.ip.IP):
                        protocols['Non-IP']['packets'] += 1
                        protocols['Non-IP']['bytes'] += packet_len # 使用 packet_len
                        continue

                    ip_pkt = eth.data
                    src_ip = socket.inet_ntoa(ip_pkt.src)
                    dst_ip = socket.inet_ntoa(ip_pkt.dst)
                    # packet_len = len(buf) # 已在前面计算

                    source_ips[src_ip]['packets'] += 1
                    source_ips[src_ip]['bytes'] += packet_len
                    dest_ips[dst_ip]['packets'] += 1
                    dest_ips[dst_ip]['bytes'] += packet_len

                    # 确定传输层协议
                    proto_name = "Other IP" # 默认值
                    if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                        proto_name = "TCP"
                    elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                        proto_name = "UDP"
                    elif isinstance(ip_pkt.data, dpkt.icmp.ICMP):
                        proto_name = "ICMP"

                    protocols[proto_name]['packets'] += 1
                    protocols[proto_name]['bytes'] += packet_len

                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, AttributeError, IndexError) as e:
                    # 处理解析错误，例如包不完整或格式未知
                    protocols['Malformed/Unknown']['packets'] += 1
                    protocols['Malformed/Unknown']['bytes'] += packet_len # 使用 packet_len
                    continue # 继续处理下一个包

        # --- 排序和选择 Top N ---
        # 按字节数排序
        sorted_src_ips_bytes = sorted(source_ips.items(), key=lambda item: item[1]['bytes'], reverse=True)
        sorted_dest_ips_bytes = sorted(dest_ips.items(), key=lambda item: item[1]['bytes'], reverse=True)

        # 协议排序 (按包数或字节数)
        sorted_protocols = sorted(protocols.items(), key=lambda item: item[1]['packets'], reverse=True)

        end_time = time.time() # 记录结束时间
        analysis_duration = end_time - start_time

        results = {
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'top_src_ip_bytes': sorted_src_ips_bytes[:top_n],
            'top_dest_ip_bytes': sorted_dest_ips_bytes[:top_n],
            'protocol_dist': dict(sorted_protocols),
            'analysis_duration': analysis_duration
        }

        result_queue.put({'status': 'done', 'data': results})

    except FileNotFoundError:
        result_queue.put({'status': 'error', 'data': f"文件未找到: {file_path}"})
    except PermissionError:
         result_queue.put({'status': 'error', 'data': f"无权限读取文件: {file_path}"})
    except ValueError as e:
        result_queue.put({'status': 'error', 'data': str(e)})
    except MemoryError:
        result_queue.put({'status': 'error', 'data': "处理文件时内存不足，文件可能过大。"})
    except Exception as e:
        error_details = traceback.format_exc()
        print(f"分析过程中发生意外错误:\n{error_details}")
        result_queue.put({'status': 'error', 'data': f"分析时发生未知错误: {e}"})
# main.py
import customtkinter as ctk
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog
import threading
import queue
import os
from analyzer import analyze_pcap # Import the analysis function

# 设置 CustomTkinter 外观
ctk.set_appearance_mode("System")  # Modes: "System" (default), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (default), "green", "dark-blue"

class IPTrafficAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("IP Traffic Analyzer")
        self.geometry("1920x1080")
        self.minsize(1024, 768)

        # --- Font Definitions ---
        self.base_font = ("Segoe UI", 12)
        self.heading_font = ("Segoe UI", 14, "bold")
        self.textbox_font = ("Consolas", 12)
        self.treeview_heading_font = ("Segoe UI", 12, "bold")
        self.treeview_row_font = ("Segoe UI", 11)

        # --- Main Layout Frames ---
        # Configure main window grid
        self.grid_rowconfigure(0, weight=0) # Navbar row
        self.grid_rowconfigure(1, weight=0) # Control Frame row
        self.grid_rowconfigure(2, weight=0) # Progress bar row
        self.grid_rowconfigure(3, weight=1) # Bottom Frame row (results)
        self.grid_columnconfigure(0, weight=1) # Main column expands

        # --- Navigation Bar ---
        self.navbar_frame = ctk.CTkFrame(self, height=35)
        self.navbar_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(5, 0))
        # Configure columns to push items to sides
        self.navbar_frame.grid_columnconfigure(0, weight=1) # Left side
        self.navbar_frame.grid_columnconfigure(1, weight=1) # Right side

        # 文件菜单（左侧）
        self.file_menu = ctk.CTkOptionMenu(self.navbar_frame,
                                         values=["导出分析结果(TXT)"],
                                         command=self.export_analysis,
                                         width=140)
        self.file_menu.grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")

        # 帮助按钮（右侧）
        self.help_button = ctk.CTkButton(self.navbar_frame,
                                       text="帮助文档",
                                       width=140,
                                       command=self.show_help)
        self.help_button.grid(row=0, column=1, padx=(5, 10), pady=5, sticky="e")

        # --- Control Frame ---
        self.control_frame = ctk.CTkFrame(self)
        self.control_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        # Configure columns within control_frame
        self.control_frame.grid_columnconfigure(0, weight=0) # Select button
        self.control_frame.grid_columnconfigure(1, weight=0) # Analyze button
        self.control_frame.grid_columnconfigure(2, weight=1) # File label (expands)
        self.control_frame.grid_columnconfigure(3, weight=0) # Status frame

        # 文件选择控件
        self.select_button = ctk.CTkButton(self.control_frame,
                                         text="选择 PCAP 文件",
                                         command=self.select_file,
                                         width=180,
                                         font=self.base_font)
        self.select_button.grid(row=0, column=0, padx=(10, 5), pady=5, sticky="w")

        # 分析按钮
        self.analyze_button = ctk.CTkButton(self.control_frame,
                                          text="开始分析",
                                          command=self.start_analysis,
                                          state=tk.DISABLED,
                                          width=120,
                                          font=self.base_font)
        self.analyze_button.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 文件标签
        self.file_label = ctk.CTkLabel(self.control_frame,
                                     text="尚未选择文件",
                                     anchor="w",
                                     font=self.base_font)
        self.file_label.grid(row=0, column=2, padx=10, pady=5, sticky="ew")

        # 状态指示区域（右侧布局）
        self.status_frame = ctk.CTkFrame(self.control_frame, fg_color="transparent")
        self.status_frame.grid(row=0, column=3, sticky="e", padx=10, pady=5)

        # 状态指示灯
        self.status_indicator_dot = ctk.CTkFrame(self.status_frame,
                                               width=20,
                                               height=20,
                                               corner_radius=10,
                                               fg_color="grey")
        self.status_indicator_dot.grid(row=0, column=0, padx=5)

        # 状态标签
        self.status_label = ctk.CTkLabel(self.status_frame,
                                       text="状态: 空闲",
                                       font=self.base_font)
        self.status_label.grid(row=0, column=1, padx=5)

        # --- Progress Bar Frame ---
        self.progress_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.progress_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 5))
        self.progressbar = ctk.CTkProgressBar(self.progress_frame)
        self.progressbar.grid(row=0, column=0, sticky="ew", padx=10)
        self.progressbar.grid_remove()

        # --- Bottom Frame for Results ---
        self.bottom_frame = ctk.CTkFrame(self)
        self.bottom_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.bottom_frame.grid_columnconfigure(0, weight=1)
        self.bottom_frame.grid_columnconfigure(1, weight=3)
        self.bottom_frame.grid_rowconfigure(0, weight=1)

        # Left column frame
        self.left_results_frame = ctk.CTkFrame(self.bottom_frame)
        self.left_results_frame.grid(row=0, column=0, padx=(0, 5), pady=0, sticky="nsew")
        self.left_results_frame.grid_rowconfigure(1, weight=0)
        self.left_results_frame.grid_rowconfigure(3, weight=1)
        self.left_results_frame.grid_columnconfigure(0, weight=1)

        # Right column frame
        self.right_results_frame = ctk.CTkFrame(self.bottom_frame)
        self.right_results_frame.grid(row=0, column=1, padx=(5, 0), pady=0, sticky="nsew")
        self.right_results_frame.grid_rowconfigure(1, weight=1)
        self.right_results_frame.grid_rowconfigure(3, weight=1)
        self.right_results_frame.grid_columnconfigure(0, weight=1)

        # Analysis Summary
        self.summary_label = ctk.CTkLabel(self.left_results_frame, text="分析摘要", font=self.heading_font)
        self.summary_label.grid(row=0, column=0, padx=5, pady=(5,0), sticky="w")
        self.summary_textbox = ctk.CTkTextbox(self.left_results_frame, height=120, state=tk.DISABLED, wrap=tk.WORD, font=self.textbox_font)
        self.summary_textbox.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")

        # Protocol Distribution
        self.proto_dist_label = ctk.CTkLabel(self.left_results_frame, text="传输层协议分布", font=self.heading_font)
        self.proto_dist_label.grid(row=2, column=0, padx=5, pady=(10, 0), sticky="w")
        self.proto_dist_textbox = ctk.CTkTextbox(self.left_results_frame, state=tk.DISABLED, wrap=tk.WORD, font=self.textbox_font)
        self.proto_dist_textbox.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")

        # Configure ttk Treeview style
        style = ttk.Style()
        bg_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkFrame"]["fg_color"])
        text_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkLabel"]["text_color"])
        selected_color = self._apply_appearance_mode(ctk.ThemeManager.theme["CTkButton"]["fg_color"])

        style.theme_use("clam")
        style.configure("Treeview",
                        background=bg_color,
                        foreground=text_color,
                        fieldbackground=bg_color,
                        font=self.treeview_row_font,
                        rowheight=int(self.treeview_row_font[1] * 2.5))
        style.map('Treeview', background=[('selected', selected_color)])
        style.configure("Treeview.Heading",
                        font=self.treeview_heading_font,
                        padding=(5, 5))

        # Top N Source IPs
        self.src_ip_label = ctk.CTkLabel(self.right_results_frame, text="Top N 源 IP (按字节数)", font=self.heading_font)
        self.src_ip_label.grid(row=0, column=0, padx=5, pady=(5, 0), sticky="w")
        self.src_ip_tree_frame = ctk.CTkFrame(self.right_results_frame, fg_color="transparent")
        self.src_ip_tree_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.src_ip_tree_frame.grid_rowconfigure(0, weight=1)
        self.src_ip_tree_frame.grid_columnconfigure(0, weight=1)

        self.src_ip_tree = ttk.Treeview(self.src_ip_tree_frame, columns=("IP Address", "Bytes", "Packets"), show="headings")
        self.src_ip_tree.heading("IP Address", text="源 IP 地址")
        self.src_ip_tree.heading("Bytes", text="总字节数")
        self.src_ip_tree.heading("Packets", text="总包数")
        self.src_ip_tree.column("IP Address", width=200, anchor=tk.W)
        self.src_ip_tree.column("Bytes", width=150, anchor=tk.E)
        self.src_ip_tree.column("Packets", width=100, anchor=tk.E)

        self.src_ip_vsb = ttk.Scrollbar(self.src_ip_tree_frame, orient="vertical", command=self.src_ip_tree.yview)
        self.src_ip_hsb = ttk.Scrollbar(self.src_ip_tree_frame, orient="horizontal", command=self.src_ip_tree.xview)
        self.src_ip_tree.configure(yscrollcommand=self.src_ip_vsb.set, xscrollcommand=self.src_ip_hsb.set)
        self.src_ip_tree.grid(row=0, column=0, sticky="nsew")
        self.src_ip_vsb.grid(row=0, column=1, sticky="ns")
        self.src_ip_hsb.grid(row=1, column=0, sticky="ew")

        # Top N Destination IPs
        self.dest_ip_label = ctk.CTkLabel(self.right_results_frame, text="Top N 目的 IP (按字节数)", font=self.heading_font)
        self.dest_ip_label.grid(row=2, column=0, padx=5, pady=(10, 0), sticky="w")
        self.dest_ip_tree_frame = ctk.CTkFrame(self.right_results_frame, fg_color="transparent")
        self.dest_ip_tree_frame.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")
        self.dest_ip_tree_frame.grid_rowconfigure(0, weight=1)
        self.dest_ip_tree_frame.grid_columnconfigure(0, weight=1)

        self.dest_ip_tree = ttk.Treeview(self.dest_ip_tree_frame, columns=("IP Address", "Bytes", "Packets"), show="headings")
        self.dest_ip_tree.heading("IP Address", text="目的 IP 地址")
        self.dest_ip_tree.heading("Bytes", text="总字节数")
        self.dest_ip_tree.heading("Packets", text="总包数")
        self.dest_ip_tree.column("IP Address", width=200, anchor=tk.W)
        self.dest_ip_tree.column("Bytes", width=150, anchor=tk.E)
        self.dest_ip_tree.column("Packets", width=100, anchor=tk.E)

        self.dest_ip_vsb = ttk.Scrollbar(self.dest_ip_tree_frame, orient="vertical", command=self.dest_ip_tree.yview)
        self.dest_ip_hsb = ttk.Scrollbar(self.dest_ip_tree_frame, orient="horizontal", command=self.dest_ip_tree.xview)
        self.dest_ip_tree.configure(yscrollcommand=self.dest_ip_vsb.set, xscrollcommand=self.dest_ip_hsb.set)
        self.dest_ip_tree.grid(row=0, column=0, sticky="nsew")
        self.dest_ip_vsb.grid(row=0, column=1, sticky="ns")
        self.dest_ip_hsb.grid(row=1, column=0, sticky="ew")

        # --- 内部变量 ---
        self.selected_file_path = None
        self.analysis_queue = queue.Queue()
        self.analysis_thread = None
        self.last_results = None

    def select_file(self):
        """打开文件对话框选择 PCAP 文件"""
        file_path = filedialog.askopenfilename(
            title="选择 PCAP 文件",
            filetypes=(("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )
        if file_path:
            self.selected_file_path = file_path
            file_name = os.path.basename(file_path)
            self.file_label.configure(text=f"已选择: {file_name}")
            self.analyze_button.configure(state=tk.NORMAL)
            self.clear_results_display()
            self.summary_textbox.configure(state=tk.NORMAL)
            self.summary_textbox.insert("1.0", "文件已选择，请点击 '开始分析'.")
            self.summary_textbox.configure(state=tk.DISABLED)
            self.update_status("状态: 空闲")
            self.update_status_indicator("grey")
        else:
            if not self.selected_file_path:
                 self.analyze_button.configure(state=tk.DISABLED)
                 self.file_label.configure(text="尚未选择文件")
                 self.update_status_indicator("grey")

    def start_analysis(self):
        """启动后台线程进行 PCAP 分析"""
        if not self.selected_file_path:
            self.update_status("错误: 请先选择一个文件", is_error=True)
            return

        # 禁用按钮，避免重复分析
        self.analyze_button.configure(state=tk.DISABLED)
        self.select_button.configure(state=tk.DISABLED)
        self.clear_results_display()

        # 显示进度条
        self.progressbar.grid()
        self.progressbar.set(0)
        self.update_status("状态: 分析中...")
        self.update_status_indicator("yellow")

        # 启动分析线程
        self.analysis_thread = threading.Thread(
            target=analyze_pcap,
            args=(self.selected_file_path, self.analysis_queue)
        )
        self.analysis_thread.daemon = True
        self.analysis_thread.start()

        # 开始检查结果队列
        self.after(100, self.check_queue)

    def check_queue(self):
        """检查分析线程的结果队列"""
        try:
            result = self.analysis_queue.get_nowait()
            if result['status'] == 'progress':
                self.progressbar.set(result['data'])
                self.after(100, self.check_queue)
            elif result['status'] == 'done':
                self.display_results(result['data'])
                self.reset_ui_after_analysis(success=True)
            elif result['status'] == 'error':
                self.update_status(f"错误: {result['data']}", is_error=True)
                self.reset_ui_after_analysis(success=False)
        except queue.Empty:
            if self.analysis_thread and self.analysis_thread.is_alive():
                self.after(100, self.check_queue)
            else:
                self.reset_ui_after_analysis(success=False)

    def clear_results_display(self):
        """清空所有结果显示区域"""
        self.summary_textbox.configure(state=tk.NORMAL)
        self.summary_textbox.delete("1.0", tk.END)
        self.summary_textbox.configure(state=tk.DISABLED)

        self.proto_dist_textbox.configure(state=tk.NORMAL)
        self.proto_dist_textbox.delete("1.0", tk.END)
        self.proto_dist_textbox.configure(state=tk.DISABLED)

        for item in self.src_ip_tree.get_children():
            self.src_ip_tree.delete(item)
        for item in self.dest_ip_tree.get_children():
            self.dest_ip_tree.delete(item)

    def display_results(self, results):
        """显示分析结果"""
        self.last_results = results

        # 更新摘要
        self.summary_textbox.configure(state=tk.NORMAL)
        self.summary_textbox.delete("1.0", tk.END)
        total_mb = results['total_bytes'] / (1024 * 1024)
        duration = results['analysis_duration']
        summary_text = (
            f"总数据包数: {results['total_packets']:,}\n"
            f"总流量: {total_mb:.2f} MB\n"
            f"分析耗时: {duration:.2f} 秒"
        )
        self.summary_textbox.insert("1.0", summary_text)
        self.summary_textbox.configure(state=tk.DISABLED)

        # 更新协议分布
        self.proto_dist_textbox.configure(state=tk.NORMAL)
        self.proto_dist_textbox.delete("1.0", tk.END)
        proto_text = ""
        for proto, stats in results['protocol_dist'].items():
            proto_percent = (stats['packets'] / results['total_packets']) * 100
            proto_mb = stats['bytes'] / (1024 * 1024)
            proto_text += f"{proto}:\n  包数: {stats['packets']:,} ({proto_percent:.1f}%)\n  流量: {proto_mb:.2f} MB\n\n"
        self.proto_dist_textbox.insert("1.0", proto_text)
        self.proto_dist_textbox.configure(state=tk.DISABLED)

        # 更新源IP表格
        for item in self.src_ip_tree.get_children():
            self.src_ip_tree.delete(item)
        for ip, stats in results['top_src_ip_bytes']:
            self.src_ip_tree.insert("", tk.END, values=(
                ip,
                f"{stats['bytes']:,}",
                f"{stats['packets']:,}"
            ))

        # 更新目的IP表格
        for item in self.dest_ip_tree.get_children():
            self.dest_ip_tree.delete(item)
        for ip, stats in results['top_dest_ip_bytes']:
            self.dest_ip_tree.insert("", tk.END, values=(
                ip,
                f"{stats['bytes']:,}",
                f"{stats['packets']:,}"
            ))

    def update_status(self, message, is_error=False):
        """更新状态标签"""
        self.status_label.configure(text=message)
        if is_error:
            self.update_status_indicator("red")

    def update_status_indicator(self, color):
        """更新状态指示灯颜色"""
        self.status_indicator_dot.configure(fg_color=color)

    def export_analysis(self, _=None):
        """导出分析结果到文本文件"""
        if not self.last_results:
            self.update_status("错误: 没有可导出的分析结果", is_error=True)
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="导出分析结果"
        )

        if not file_path:
            return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # 写入基本信息
                f.write("=== IP流量分析报告 ===\n\n")
                
                # 写入摘要
                f.write("--- 分析摘要 ---\n")
                total_mb = self.last_results['total_bytes'] / (1024 * 1024)
                f.write(f"总数据包数: {self.last_results['total_packets']:,}\n")
                f.write(f"总流量: {total_mb:.2f} MB\n")
                f.write(f"分析耗时: {self.last_results['analysis_duration']:.2f} 秒\n\n")

                # 写入协议分布
                f.write("--- 协议分布 ---\n")
                for proto, stats in self.last_results['protocol_dist'].items():
                    proto_percent = (stats['packets'] / self.last_results['total_packets']) * 100
                    proto_mb = stats['bytes'] / (1024 * 1024)
                    f.write(f"{proto}:\n")
                    f.write(f"  包数: {stats['packets']:,} ({proto_percent:.1f}%)\n")
                    f.write(f"  流量: {proto_mb:.2f} MB\n\n")

                # 写入Top N源IP
                f.write("--- Top N 源 IP (按字节数) ---\n")
                for ip, stats in self.last_results['top_src_ip_bytes']:
                    ip_mb = stats['bytes'] / (1024 * 1024)
                    f.write(f"IP: {ip}\n")
                    f.write(f"  总字节数: {stats['bytes']:,} ({ip_mb:.2f} MB)\n")
                    f.write(f"  总包数: {stats['packets']:,}\n\n")

                # 写入Top N目的IP
                f.write("--- Top N 目的 IP (按字节数) ---\n")
                for ip, stats in self.last_results['top_dest_ip_bytes']:
                    ip_mb = stats['bytes'] / (1024 * 1024)
                    f.write(f"IP: {ip}\n")
                    f.write(f"  总字节数: {stats['bytes']:,} ({ip_mb:.2f} MB)\n")
                    f.write(f"  总包数: {stats['packets']:,}\n\n")

            self.update_status("分析结果已成功导出")
        except Exception as e:
            self.update_status(f"导出失败: {str(e)}", is_error=True)

    def show_help(self):
        """显示帮助文档"""
        help_window = ctk.CTkToplevel(self)
        help_window.title("帮助文档")
        help_window.geometry("600x400")
        help_window.minsize(400, 300)

        # 使帮助窗口置于主窗口之上
        help_window.transient(self)
        help_window.grab_set()

        # 创建文本框
        help_text = ctk.CTkTextbox(help_window, wrap=tk.WORD, font=self.textbox_font)
        help_text.pack(expand=True, fill="both", padx=10, pady=10)

        # 帮助文档内容
        help_content = """IP流量分析器使用说明

1. 基本操作
   - 点击"选择 PCAP 文件"按钮选择要分析的文件
   - 支持的文件格式：.pcap, .pcapng
   - 点击"开始分析"按钮开始分析
   - 分析过程中可以查看进度条

2. 分析结果
   - 分析摘要：显示总包数、总流量等基本信息
   - 协议分布：显示各传输层协议的统计信息
   - Top N 源/目的 IP：按流量排序的IP地址列表

3. 导出功能
   - 点击左上角的"导出分析结果(TXT)"
   - 选择保存位置
   - 导出的文件包含完整的分析报告

4. 注意事项
   - 大文件分析可能需要较长时间
   - 分析过程中请勿关闭程序
   - 如果出现错误，请检查文件格式是否正确

5. 状态指示
   - 灰色：空闲
   - 黄色：分析中
   - 绿色：分析完成
   - 红色：发生错误

如需技术支持，请联系管理员。"""

        help_text.insert("1.0", help_content)
        help_text.configure(state=tk.DISABLED)

    def reset_ui_after_analysis(self, success=True):
        """重置UI状态"""
        self.analyze_button.configure(state=tk.NORMAL)
        self.select_button.configure(state=tk.NORMAL)
        self.progressbar.grid_remove()
        
        if success:
            self.update_status("状态: 分析完成")
            self.update_status_indicator("green")
        else:
            self.update_status_indicator("red")

if __name__ == "__main__":
    app = IPTrafficAnalyzerApp()
    app.mainloop()
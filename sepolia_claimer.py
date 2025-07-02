class SepoliaTokenClaimer:
    def __init__(self, root):
        self.root = root
        self.root.title("zama测试网代币领取工具")
        self.root.geometry("900x700")
        
        # 配置变量
        self.rpc_url = tk.StringVar(value="https://rpc.sepolia.ethpandaops.io")
        self.contract_address = tk.StringVar(value="0x3edf60dd017ace33a0220f78741b5581c385a1ba")
        self.private_key = tk.StringVar(value="")
        self.wallet_address = tk.StringVar(value="")
        self.interval = tk.IntVar(value=300)  # 5分钟间隔
        self.gas_price = tk.IntVar(value=20)  # Gwei
        self.gas_limit = tk.IntVar(value=100000)
        
        self.is_running = False
        self.claim_thread = None
        self.web3 = None
        
        # 创建GUI
        self.create_widgets()
        
        # 加载配置
        self.load_config()
        
        # 计数器
        self.success_count = 0
        self.fail_count = 0
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 网络配置区域
        network_frame = ttk.LabelFrame(main_frame, text="网络配置", padding="10")
        network_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(network_frame, text="RPC节点:").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(network_frame, textvariable=self.rpc_url, width=70).grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(network_frame, text="合约地址:").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(network_frame, textvariable=self.contract_address, width=70).grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # 钱包配置区域
        wallet_frame = ttk.LabelFrame(main_frame, text="钱包配置", padding="10")
        wallet_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(wallet_frame, text="私钥:").grid(row=0, column=0, sticky=tk.W, pady=2)
        private_key_entry = ttk.Entry(wallet_frame, textvariable=self.private_key, width=70, show="*")
        private_key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=2)
        
        ttk.Label(wallet_frame, text="钱包地址:").grid(row=1, column=0, sticky=tk.W, pady=2)
        wallet_entry = ttk.Entry(wallet_frame, textvariable=self.wallet_address, width=70, state="readonly")
        wallet_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        
        # 添加验证私钥按钮
        ttk.Button(wallet_frame, text="验证私钥", command=self.validate_private_key).grid(row=2, column=1, sticky=tk.W, pady=2)
        
        # 绑定私钥变化事件
        self.private_key.trace('w', self.update_wallet_address)
        
        # 交易配置区域
        tx_frame = ttk.LabelFrame(main_frame, text="交易配置", padding="10")
        tx_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(tx_frame, text="Gas价格(Gwei):").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(tx_frame, textvariable=self.gas_price, width=20).grid(row=0, column=1, sticky=tk.W, pady=2)
        
        ttk.Label(tx_frame, text="Gas限制:").grid(row=0, column=2, sticky=tk.W, pady=2, padx=(20, 0))
        ttk.Entry(tx_frame, textvariable=self.gas_limit, width=20).grid(row=0, column=3, sticky=tk.W, pady=2)
        
        ttk.Label(tx_frame, text="领取间隔(秒):").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(tx_frame, textvariable=self.interval, width=20).grid(row=1, column=1, sticky=tk.W, pady=2)
        
        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Button(button_frame, text="连接网络", command=self.connect_network).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="检查余额", command=self.check_balance).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="测试调用数据", command=self.test_call_data).pack(side=tk.LEFT, padx=(0, 5))
        
        self.start_button = ttk.Button(button_frame, text="开始领取", command=self.start_claiming)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(button_frame, text="停止领取", command=self.stop_claiming, state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(button_frame, text="保存配置", command=self.save_config).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(button_frame, text="清空记录", command=self.clear_logs).pack(side=tk.LEFT)
        
        # 状态区域
        status_frame = ttk.LabelFrame(main_frame, text="状态信息", padding="10")
        status_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.network_status_label = ttk.Label(status_frame, text="网络状态: 未连接", foreground="red")
        self.network_status_label.pack(anchor=tk.W)
        
        self.balance_label = ttk.Label(status_frame, text="ETH余额: -")
        self.balance_label.pack(anchor=tk.W)
        
        self.claim_status_label = ttk.Label(status_frame, text="领取状态: 未启动", foreground="red")
        self.claim_status_label.pack(anchor=tk.W)
        
        self.next_claim_label = ttk.Label(status_frame, text="下次领取: -")
        self.next_claim_label.pack(anchor=tk.W)
        
        self.success_count_label = ttk.Label(status_frame, text="成功次数: 0")
        self.success_count_label.pack(anchor=tk.W)
        
        self.fail_count_label = ttk.Label(status_frame, text="失败次数: 0")
        self.fail_count_label.pack(anchor=tk.W)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="领取记录", padding="10")
        log_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=12)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 设置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
        network_frame.columnconfigure(1, weight=1)
        wallet_frame.columnconfigure(1, weight=1)
        
    def log_message(self, message):
        """添加日志消息"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # 限制日志长度
        lines = int(self.log_text.index('end-1c').split('.')[0])
        if lines > 1000:
            self.log_text.delete('1.0', '100.end')
    
    def update_wallet_address(self, *args):
        """当私钥改变时更新钱包地址"""
        try:
            private_key = self.private_key.get().strip()
            
            # 移除可能的0x前缀
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            
            # 检查是否为64位十六进制字符串
            if private_key and len(private_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in private_key):
                account = Account.from_key('0x' + private_key)
                self.wallet_address.set(account.address)
                self.log_message(f"✅ 钱包地址已生成: {account.address}")
            else:
                self.wallet_address.set("")
                if private_key:  # 只有当输入不为空时才显示错误
                    self.log_message("❌ 私钥格式错误：必须是64位十六进制字符串")
        except Exception as e:
            self.wallet_address.set("")
            if self.private_key.get().strip():  # 只有当输入不为空时才显示错误
                self.log_message(f"❌ 私钥解析失败: {str(e)}")
                messagebox.showerror("私钥错误", "私钥格式不正确，请检查是否为64位十六进制字符串")
    
    def validate_private_key(self):
        """手动验证私钥格式"""
        private_key = self.private_key.get().strip()
        
        if not private_key:
            messagebox.showwarning("验证结果", "请先输入私钥")
            return
        
        # 移除可能的0x前缀
        if private_key.startswith('0x'):
            private_key = private_key[2:]
            
        issues = []
        
        # 检查长度
        if len(private_key) != 64:
            issues.append(f"长度错误：当前{len(private_key)}位，需要64位")
        
        # 检查字符
        invalid_chars = [c for c in private_key if c not in '0123456789abcdefABCDEF']
        if invalid_chars:
            issues.append(f"包含无效字符：{', '.join(set(invalid_chars))}")
        
        if issues:
            messagebox.showerror("私钥验证失败", 
                               f"发现以下问题：\n\n" + '\n'.join(f"• {issue}" for issue in issues) + 
                               f"\n\n正确格式示例：\n1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        else:
            try:
                account = Account.from_key('0x' + private_key)
                messagebox.showinfo("验证成功", 
                                  f"✅ 私钥格式正确！\n\n钱包地址：\n{account.address}")
                # 手动触发地址更新
                self.update_wallet_address()
            except Exception as e:
                messagebox.showerror("验证失败", f"私钥无法解析：{str(e)}")
    
    def connect_network(self):
        """连接到Sepolia网络"""
        try:
            self.log_message("正在连接Sepolia测试网...")
            
            self.web3 = Web3(Web3.HTTPProvider(self.rpc_url.get()))
            
            if self.web3.is_connected():
                chain_id = self.web3.eth.chain_id
                if chain_id == 11155111:  # Sepolia chain ID
                    self.network_status_label.config(text="网络状态: 已连接 (Sepolia)", foreground="green")
                    self.log_message("✅ 成功连接到Sepolia测试网")
                    return True
                else:
                    raise Exception(f"错误的网络ID: {chain_id}, 应该是11155111 (Sepolia)")
            else:
                raise Exception("无法连接到网络")
                
        except Exception as e:
            error_msg = f"网络连接失败: {str(e)}"
            self.network_status_label.config(text="网络状态: 连接失败", foreground="red")
            self.log_message(f"❌ {error_msg}")
            messagebox.showerror("连接失败", error_msg)
            return False
    
    def check_balance(self):
        """检查ETH余额"""
        try:
            if not self.web3:
                messagebox.showerror("错误", "请先连接网络")
                return
                
            if not self.wallet_address.get():
                messagebox.showerror("错误", "钱包地址为空，请检查私钥格式是否正确\n\n私钥要求：\n- 64位十六进制字符串\n- 不包含0x前缀\n- 不包含空格或特殊字符")
                return
            
            address = Web3.to_checksum_address(self.wallet_address.get())
            balance_wei = self.web3.eth.get_balance(address)
            balance_eth = self.web3.from_wei(balance_wei, 'ether')
            
            self.balance_label.config(text=f"ETH余额: {balance_eth:.6f} ETH")
            self.log_message(f"💰 当前ETH余额: {balance_eth:.6f} ETH")
            
        except Exception as e:
            error_msg = f"余额查询失败: {str(e)}"
            self.log_message(f"❌ {error_msg}")
            messagebox.showerror("查询失败", error_msg)
    
    def test_call_data(self):
        """测试生成的调用数据格式"""
        try:
            if not self.wallet_address.get():
                messagebox.showerror("错误", "请先输入私钥生成钱包地址")
                return
            
            # 生成调用数据
            wallet_address = self.wallet_address.get()[2:].lower()  # 移除0x前缀
            wallet_param = wallet_address.zfill(64)  # 补足64位（32字节）
            call_data = '0x6a627842' + wallet_param
            
            self.log_message("🧪 测试调用数据格式:")
            self.log_message(f"  钱包地址: {self.wallet_address.get()}")
            self.log_message(f"  方法ID: 0x6a627842")
            self.log_message(f"  地址参数: {wallet_param}")
            self.log_message(f"  完整调用数据: {call_data}")
            self.log_message(f"  数据长度: {len(call_data)} 字符")
            
            # 与成功交易对比
            success_data = "0x6a627842000000000000000000000000a896713c759b12254fbd0fafeb61e06b6303c4bb"
            self.log_message(f"  成功案例: {success_data}")
            self.log_message(f"  格式匹配: {'✅ 是' if len(call_data) == len(success_data) else '❌ 否'}")
            
            messagebox.showinfo("调用数据测试", 
                              f"✅ 调用数据已生成\n\n"
                              f"方法ID: 0x6a627842\n"
                              f"地址参数: {wallet_param}\n\n"
                              f"完整数据: {call_data[:20]}...\n"
                              f"长度: {len(call_data)} 字符")
            
        except Exception as e:
            self.log_message(f"❌ 测试失败: {str(e)}")
            messagebox.showerror("测试失败", str(e))
    
    def claim_token(self):
        """执行代币领取"""
        try:
            if not self.web3 or not self.private_key.get():
                raise Exception("请先连接网络并输入私钥")
            
            # 处理私钥（移除可能的0x前缀）
            private_key = self.private_key.get().strip()
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            account = Account.from_key('0x' + private_key)
            
            # 构建智能合约调用数据
            # 方法ID: 0x6a627842 + 钱包地址参数（32字节）
            wallet_address = account.address[2:].lower()  # 移除0x前缀
            wallet_param = wallet_address.zfill(64)  # 补足64位（32字节）
            call_data = '0x6a627842' + wallet_param
            
            # 构建交易
            transaction = {
                'to': Web3.to_checksum_address(self.contract_address.get()),
                'value': 0,
                'gas': self.gas_limit.get(),
                'gasPrice': self.web3.to_wei(self.gas_price.get(), 'gwei'),
                'nonce': self.web3.eth.get_transaction_count(account.address),
                'data': call_data,  # 方法ID + 钱包地址参数
                'chainId': 11155111  # Sepolia chain ID
            }
            
            self.log_message(f"📋 调用数据: {call_data}")
            self.log_message(f"  - 方法ID: 0x6a627842")
            self.log_message(f"  - 地址参数: {wallet_param}")
            
            # 签名交易
            signed_txn = self.web3.eth.account.sign_transaction(transaction, self.private_key.get())
            
            # 发送交易
            tx_hash = self.web3.eth.send_raw_transaction(signed_txn.rawTransaction)
            tx_hash_hex = tx_hash.hex()
            
            self.log_message(f"📤 交易已发送: {tx_hash_hex}")
            self.log_message("⏳ 等待交易确认...")
            
            # 等待交易确认
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            
            if receipt.status == 1:
                self.success_count += 1
                self.success_count_label.config(text=f"成功次数: {self.success_count}")
                self.log_message(f"✅ 代币领取成功! Gas使用: {receipt.gasUsed}")
                self.log_message(f"🔗 交易链接: https://sepolia.etherscan.io/tx/{tx_hash_hex}")
                return True
            else:
                self.fail_count += 1
                self.fail_count_label.config(text=f"失败次数: {self.fail_count}")
                self.log_message(f"❌ 交易执行失败")
                return False
                
        except Exception as e:
            self.fail_count += 1
            self.fail_count_label.config(text=f"失败次数: {self.fail_count}")
            error_msg = str(e)
            
            # 解析常见错误
            if "insufficient funds" in error_msg.lower():
                error_msg = "ETH余额不足，无法支付Gas费用"
            elif "nonce too low" in error_msg.lower():
                error_msg = "Nonce值过低，请稍后重试"
            elif "replacement transaction underpriced" in error_msg.lower():
                error_msg = "交易费用过低，请提高Gas价格"
            
            self.log_message(f"❌ 领取失败: {error_msg}")
            return False
    
    def claiming_loop(self):
        """领取循环"""
        while self.is_running:
            try:
                self.log_message("🚀 开始尝试领取代币...")
                self.claim_token()
                
                if self.is_running:
                    # 等待指定间隔
                    for i in range(self.interval.get()):
                        if not self.is_running:
                            break
                        remaining = self.interval.get() - i
                        self.next_claim_label.config(text=f"下次领取: {remaining}秒后")
                        time.sleep(1)
                        
            except Exception as e:
                self.log_message(f"❌ 循环异常: {str(e)}")
                time.sleep(10)  # 异常后等待10秒再继续
    
    def start_claiming(self):
        """开始领取"""
        if not self.web3:
            messagebox.showerror("错误", "请先连接网络")
            return
            
        if not self.private_key.get():
            messagebox.showerror("错误", "请输入私钥")
            return
            
        if self.interval.get() < 60:
            result = messagebox.askyesno("警告", "领取间隔小于60秒可能会被限制，是否继续？")
            if not result:
                return
                
        self.is_running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.claim_status_label.config(text="领取状态: 运行中", foreground="green")
        
        # 启动领取线程
        self.claim_thread = threading.Thread(target=self.claiming_loop, daemon=True)
        self.claim_thread.start()
        
        self.log_message("🚀 开始自动领取代币")
    
    def stop_claiming(self):
        """停止领取"""
        self.is_running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.claim_status_label.config(text="领取状态: 已停止", foreground="red")
        self.next_claim_label.config(text="下次领取: -")
        
        self.log_message("⏹️ 停止自动领取")
    
    def clear_logs(self):
        """清空日志"""
        self.log_text.delete('1.0', tk.END)
        self.success_count = 0
        self.fail_count = 0
        self.success_count_label.config(text="成功次数: 0")
        self.fail_count_label.config(text="失败次数: 0")
        self.log_message("📝 日志已清空")
    
    def save_config(self):
        """保存配置"""
        config = {
            "rpc_url": self.rpc_url.get(),
            "contract_address": self.contract_address.get(),
            "gas_price": self.gas_price.get(),
            "gas_limit": self.gas_limit.get(),
            "interval": self.interval.get()
        }
        
        try:
            with open("sepolia_config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            self.log_message("💾 配置已保存")
            messagebox.showinfo("成功", "配置已保存到 sepolia_config.json")
        except Exception as e:
            error_msg = f"保存配置失败: {str(e)}"
            self.log_message(f"❌ {error_msg}")
            messagebox.showerror("错误", error_msg)
    
    def load_config(self):
        """加载配置"""
        try:
            if os.path.exists("sepolia_config.json"):
                with open("sepolia_config.json", "r", encoding="utf-8") as f:
                    config = json.load(f)
                
                self.rpc_url.set(config.get("rpc_url", "https://rpc.sepolia.ethpandaops.io"))
                self.contract_address.set(config.get("contract_address", "0x3edf60dd017ace33a0220f78741b5581c385a1ba"))
                self.gas_price.set(config.get("gas_price", 20))
                self.gas_limit.set(config.get("gas_limit", 100000))
                self.interval.set(config.get("interval", 300))
                
                self.log_message("📂 配置已加载")
        except Exception as e:
            self.log_message(f"❌ 加载配置失败: {str(e)}")

def main():
    root = tk.Tk()
    app = SepoliaTokenClaimer(root)
    
    # 处理窗口关闭事件
    def on_closing():
        if app.is_running:
            app.stop_claiming()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main() 

import boto3
from botocore.exceptions import ClientError
import socks
import socket
import time
import random
import requests
import string
import threading
from botocore.config import Config
from concurrent.futures import ThreadPoolExecutor
import logging
from tabulate import tabulate
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import track
import sys
from rich.progress import Progress

# 日志设置，只保留一个配置
# 设置日志（只写文件）
logging.getLogger().handlers = []
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("ec2_launch.log")]
)

logger = logging.getLogger(__name__)

# 全局变量
used_ua_lock = threading.Lock()
used_country_lock = threading.Lock()
last_used_country = None
last_used_ua = None
used_user_agents = []
success_counter = 0
failure_counter = 0
counter_lock = threading.Lock()

# 扩展区域列表
AWS_REGIONS = {
    '1': {'name': '新加坡', 'code': 'ap-southeast-1', 'ami': 'ami-0c1926bfdbdaaa772'},
    '2': {'name': '东京', 'code': 'ap-northeast-1', 'ami': 'ami-00648442d08105c3b'},
    '3': {'name': '香港', 'code': 'ap-east-1', 'ami': 'ami-042f39aeafd5fd528'},
    '4': {'name': '弗吉尼亚', 'code': 'us-east-1', 'ami': 'ami-06db4d78cb1318c75'},
    '5': {'name': '俄勒冈', 'code': 'us-west-2', 'ami': 'ami-0d70546e43a6e4ec6'}
}
selected_region = None
disk_size = 8  # 默认硬盘大小


def load_user_agents(ua_file='ua.txt'):
    """加载User-Agent列表，如文件不存在则创建默认文件"""
    default_user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    ]
    try:
        with open(ua_file, 'r', encoding='utf-8') as f:
            user_agents = [line.strip() for line in f if line.strip()]
        if not user_agents:
            raise FileNotFoundError("UA文件为空")
        logger.info(f"从 {ua_file} 加载了 {len(user_agents)} 个User-Agent")
        return user_agents
    except FileNotFoundError:
        logger.warning(f"UA文件 {ua_file} 不存在或为空，创建默认文件")
        with open(ua_file, 'w', encoding='utf-8') as f:
            for ua in default_user_agents:
                f.write(f"{ua}\n")
        return default_user_agents


def get_random_user_agent():
    """获取随机User-Agent，避免重复使用"""
    global last_used_ua, used_user_agents
    all_user_agents = load_user_agents()
    with used_ua_lock:
        if len(used_user_agents) >= len(all_user_agents):
            logger.info("所有User-Agent都已使用过，重置使用记录")
            used_user_agents.clear()
            if last_used_ua in all_user_agents:
                used_user_agents.append(last_used_ua)  # 保留上一次 UA
        available_agents = [ua for ua in all_user_agents if ua not in used_user_agents and ua != last_used_ua]
        if not available_agents:
            available_agents = [ua for ua in all_user_agents if ua != last_used_ua] or all_user_agents
        selected_ua = random.choice(available_agents)
        last_used_ua = selected_ua
        used_user_agents.append(selected_ua)
    return selected_ua


def parse_proxy_url(proxy_url):
    """解析代理URL格式，支持HTTP和SOCKS5代理"""
    if proxy_url.startswith('socks5://'):
        proxy_type = 'socks5'
        proxy_auth_and_host = proxy_url.replace('socks5://', '')
    elif proxy_url.startswith('http://'):
        proxy_type = 'http'
        proxy_auth_and_host = proxy_url.replace('http://', '')
    else:
        proxy_type = 'http'
        proxy_auth_and_host = proxy_url

    if '@' in proxy_auth_and_host:
        auth_part, host_part = proxy_auth_and_host.split('@', 1)
        proxy_user, proxy_pass = auth_part.split(':', 1) if ':' in auth_part else (auth_part, None)
        proxy_host, proxy_port = host_part.rsplit(':', 1) if ':' in host_part else (host_part, None)
    else:
        proxy_user, proxy_pass = None, None
        proxy_host, proxy_port = proxy_auth_and_host.rsplit(':', 1) if ':' in proxy_auth_and_host else (
            proxy_auth_and_host, None)

    if not proxy_port:
        raise ValueError(f"Invalid proxy format, missing port: {proxy_url}")
    return proxy_type, proxy_host, int(proxy_port), proxy_user, proxy_pass


def get_proxy_real_ip(proxy_url):
    """通过代理获取真实IP地址"""
    try:
        response = requests.get("https://ipinfo.io/json", proxies={"http": proxy_url, "https": proxy_url}, timeout=10)
        response.raise_for_status()
        return response.json().get("ip", "未知IP")
    except requests.RequestException as e:
        return f"代理连接错误: {str(e)}"


def format_access_key(access_key):
    """格式化AccessKey显示，隐藏部分字符"""
    return f"{access_key[:21]}" if len(access_key) >= 21 else access_key


def read_aws_keys(file_path):
    """从文件读取AWS密钥"""
    keys = []
    with open(file_path, 'r') as file:
        for line in file:
            if not line.strip():
                continue
            parts = line.strip().split('\t')
            if len(parts) != 2:
                logger.warning(f"无效的密钥行: {line.strip()}")
                continue
            keys.append(parts)
    return keys


def fetch_proxy_from_country(country_code=None):
    """获取指定国家的代理，如未指定则随机选择"""
    global last_used_country
    random_session = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    country_codes = ['BR', 'GB', 'DK', 'DE', 'FR', 'ES', 'IL', 'AT', 'GE', 'NG', 'AM', 'PK', 'ML', 'NL', 'LB', 'AR',
                     'KW', 'VN', 'TZ', 'OM', 'TR', 'GE', 'BA', 'LK', 'MA', 'AM', 'PE', 'CO', 'KG', 'RS', 'SK', 'TJ',
                     'AZ', 'AG', 'BG', 'LA', 'CG', 'EG', 'ET', 'MD', 'FI', 'PH', 'ZA', 'IE', 'GH', 'JM', 'GT', 'PE',
                     'HU', 'JP', 'LV', 'CZ', 'MU', 'NO', 'GY']

    with used_country_lock:
        if country_code is None:
            available_countries = [c for c in country_codes if c != last_used_country]
            country_code = random.choice(available_countries)
            last_used_country = country_code
    proxy_user = f"accountId-4259-tunnelId-6084-area-{country_code}-sessID-{random_session}-sessTime-10"
    proxy_pass = "0giZQF"
    proxy_url = f"http://{proxy_user}:{proxy_pass}@proxyas.starryproxy.com:10000"
    return proxy_url, country_code


def get_startup_script():
    """生成实例启动脚本，支持大硬盘和SOCKS5代理服务"""
    global disk_size

    # 确定根卷大小和额外卷配置
    max_volume_size = 16000  # gp2卷最大16TB

    if disk_size <= max_volume_size:
        # 如果总硬盘大小不超过16000GB，全部分配给根卷
        root_volume_size = disk_size
        additional_volumes = None
    else:
        # 如果总硬盘大小超过16000GB，根卷分配16000GB，超出部分分配给额外卷
        root_volume_size = max_volume_size
        additional_size = disk_size - max_volume_size
        additional_volumes = []

        volume_index = 1
        remaining_size = additional_size
        while remaining_size > 0:
            volume_size = min(max_volume_size, remaining_size)
            device_name = f'/dev/xvd{chr(102 + volume_index)}'
            additional_volumes.append((device_name, volume_size))
            remaining_size -= volume_size
            volume_index += 1

    # 构建启动脚本 - 基础部分
    script = f"""#!/bin/bash
# 创建持久化设置脚本
cat > /root/setup-persistent.sh << 'EOFSETUP'
#!/bin/bash

# 日志函数
log() {{
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/persistent-setup.log
}}

# 记录开始执行
log "开始执行持久化设置脚本"

# 设置SSH配置
log "配置SSH"
sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# 设置root密码 - 多次尝试确保成功
log "设置root密码"
for i in {{1..5}}; do
    echo 'root:@Zy123456789' | chpasswd
    if [ $? -eq 0 ]; then
        log "密码设置成功"
        break
    else
        log "密码设置尝试 $i 失败，等待重试"
        sleep 5
    fi
done

# 创建启动记录
log "创建硬盘信息记录"
echo "系统启动时间: $(date)" > /root/startup.log
echo "Root密码: @Zy123456789" >> /root/startup.log
echo "根卷大小: {root_volume_size}GB" >> /root/startup.log
"""

    # 硬盘处理脚本 - 如果有额外卷
    if additional_volumes:
        for idx, (device, size) in enumerate(additional_volumes):
            mount_point = f"/mnt/data{idx + 1}"
            script += f"""
# 处理额外卷 {device} ({size}GB)
log "处理额外卷 {device} ({size}GB)"
echo "正在处理卷 {device} ({size}GB)..." >> /root/startup.log
if [ -b {device} ]; then
    parted -s {device} mklabel gpt
    parted -s {device} unit GB mkpart primary 0 {size}
    # 等待分区表更新
    sleep 5
    # 确认分区1存在
    if [ -b {device}1 ]; then
        mkfs.ext4 {device}1
        mkdir -p {mount_point}
        mount {device}1 {mount_point}
        chmod 777 {mount_point}
        echo "{device}1 {mount_point} ext4 defaults 0 0" >> /etc/fstab
        echo "额外卷 {device} ({size}GB) 已挂载到 {mount_point}" >> /root/startup.log
    else
        log "错误: 分区 {device}1 未创建成功"
        echo "错误: 分区 {device}1 未创建成功" >> /root/startup.log
    fi
else
    log "错误: 设备 {device} 不存在"
    echo "错误: 设备 {device} 不存在" >> /root/startup.log
fi
"""

    # 添加磁盘信息记录
    script += """
# 记录分区信息
log "记录分区信息"
echo -e "\\n\\n磁盘分区信息:" >> /root/startup.log
fdisk -l >> /root/startup.log

# 记录磁盘使用情况
echo -e "\\n\\n磁盘使用情况:" >> /root/startup.log
df -h >> /root/startup.log

# 检查SOCKS5服务是否已安装
if [ -f "/usr/bin/3proxy" ] && [ -f "/etc/3proxy/3proxy.cfg" ] && (pgrep 3proxy > /dev/null); then
    log "SOCKS5服务已安装并运行"
else
    log "开始安装轻量级SOCKS5服务"

    # 等待网络就绪
    for i in {1..15}; do
        if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            log "网络连接正常"
            break
        fi
        log "等待网络连接... ($i/15)"
        sleep 5
    done

    # 安装基本工具
    log "安装基本工具"
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y wget gcc make
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y wget gcc make
    fi

    # 下载并编译3proxy
    log "下载并编译3proxy"
    cd /tmp
    wget --no-check-certificate https://github.com/z3APA3A/3proxy/archive/0.9.3.tar.gz
    tar -xzvf 0.9.3.tar.gz
    cd 3proxy-0.9.3
    make -f Makefile.Linux
    mkdir -p /usr/bin/
    mkdir -p /etc/3proxy/
    cp bin/3proxy /usr/bin/

    # 创建用户
    log "创建SOCKS5用户"
    useradd -M -s /usr/sbin/nologin 10010 2>/dev/null || true
    echo "10010:10010" | chpasswd

    # 创建3proxy配置文件
    log "配置3proxy"
    cat > /etc/3proxy/3proxy.cfg << 'EOFCONF'
#!/usr/bin/3proxy

# 基本设置
nserver 8.8.8.8
nserver 8.8.4.4
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

# 用户认证
users 10010:CL:10010

# 允许所有访问
auth strong
allow 10010

# 日志
log /var/log/3proxy.log D
logformat "- +_L%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"

# 启动SOCKS5代理服务器，监听所有接口的11688端口
socks -p11688
EOFCONF

    # 创建systemd服务
    log "创建3proxy服务"
    cat > /etc/systemd/system/3proxy.service << 'EOFSERVICE'
[Unit]
Description=3proxy Proxy Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/3proxy /etc/3proxy/3proxy.cfg
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOFSERVICE

    # 启动服务
    log "启动3proxy服务"
    if command -v systemctl &> /dev/null; then
        systemctl enable 3proxy
        systemctl start 3proxy
        log "3proxy状态: $(systemctl status 3proxy | grep Active || echo '未知')"
    else
        # 兼容无systemd的系统
        nohup /usr/bin/3proxy /etc/3proxy/3proxy.cfg &
        echo "nohup /usr/bin/3proxy /etc/3proxy/3proxy.cfg &" >> /etc/rc.local
        chmod +x /etc/rc.local
        log "3proxy已启动 (无systemd模式)"
    fi

    # 验证服务是否运行
    sleep 3
    if pgrep 3proxy > /dev/null; then
        log "SOCKS5服务(3proxy)启动成功"
    else
        log "SOCKS5服务启动失败，将在下一次运行时重试"
    fi
fi

# 重启SSH服务
log "重启SSH服务"
if command -v systemctl &> /dev/null; then
    systemctl restart sshd || systemctl restart ssh || true
else
    service sshd restart || service ssh restart || true
fi

# 最后再次设置密码确保成功
log "最终确认密码设置"
echo 'root:@Zy123456789' | chpasswd

log "持久化设置脚本执行完成"
exit 0
EOFSETUP

# 设置脚本权限
chmod +x /root/setup-persistent.sh

# 创建crontab任务，确保系统启动后持续尝试执行脚本直到成功
(crontab -l 2>/dev/null; echo "*/5 * * * * /root/setup-persistent.sh") | crontab -

# 创建systemd服务（如果系统支持）
if command -v systemctl &> /dev/null; then
    cat > /etc/systemd/system/persistent-setup.service << 'EOF'
[Unit]
Description=Persistent Setup Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/root/setup-persistent.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    # 启用服务
    systemctl enable persistent-setup.service
    systemctl start persistent-setup.service
fi

# 立即执行一次设置脚本
/root/setup-persistent.sh &

# 在rc.local中添加启动执行（兼容旧系统）
if [ -f /etc/rc.local ]; then
    sed -i '/exit 0/i /root/setup-persistent.sh &' /etc/rc.local
else
    echo '#!/bin/bash' > /etc/rc.local
    echo '/root/setup-persistent.sh &' >> /etc/rc.local
    echo 'exit 0' >> /etc/rc.local
    chmod +x /etc/rc.local
fi
"""
    return script


def create_boto3_session_with_proxy(access_key, secret_key, proxy_url, user_agent):
    """创建带有代理配置的boto3会话"""
    try:
        proxy_type, proxy_host, proxy_port, proxy_user, proxy_pass = parse_proxy_url(proxy_url)
        session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)

        if proxy_type == 'http':
            proxies = {'http': proxy_url, 'https': proxy_url}
            return session, proxies, user_agent
        elif proxy_type == 'socks5':
            socks.set_default_proxy(
                socks.SOCKS5, proxy_host, proxy_port, rdns=True,
                username=proxy_user, password=proxy_pass
            )
            socket.socket = socks.socksocket
            return session, None, user_agent
    except Exception as e:
        logger.error(f"创建代理会话失败: {str(e)}")
        return None, None, user_agent


def test_proxy_connection(proxy_url, user_agent, timeout=10):
    """测试代理连接是否正常"""
    try:
        response = requests.get(
            "https://www.amazon.com",
            proxies={"http": proxy_url, "https": proxy_url},
            headers={'User-Agent': user_agent},
            timeout=timeout,
            allow_redirects=False
        )
        response.raise_for_status()
        return True, "代理连接正常"
    except requests.RequestException as e:
        return False, f"代理连接失败: {str(e)}"


def generate_random_request_parameters():
    """生成随机请求参数，用于伪装请求"""
    instance_types = ['t3.micro']
    name_prefixes = ['test', 'dev', 'web', 'app', 'svc', 'node']
    random_name = f"{random.choice(name_prefixes)}-{random.randint(1000, 9999)}"
    tags = [{'Key': 'Name', 'Value': random_name}] if random.random() < 0.7 else []
    if random.random() < 0.3:
        tags.append({'Key': 'Env', 'Value': random.choice(['prod', 'dev', 'test'])})
    return {'instance_type': random.choice(instance_types), 'tags': tags}


def launch_ec2_instance(access_key, secret_key, proxy_url, country_code=None):
    """启动EC2实例"""
    global selected_region, disk_size
    display_key = format_access_key(access_key)
    user_agent = get_random_user_agent()
    original_socket = socket.socket
    proxy_ip = "未知"  # 初始化proxy_ip变量

    try:
        # 测试代理连接
        proxy_working, proxy_message = test_proxy_connection(proxy_url, user_agent)
        if not proxy_working:
            logger.error(f"{display_key} = {proxy_message}")
            return False, "代理连接失败", country_code, proxy_ip

        # 获取代理IP
        proxy_ip = get_proxy_real_ip(proxy_url)
        region_code = selected_region['code']
        region_name = selected_region['name']
        default_ami = selected_region['ami']
        logger.info(
            f"{display_key} = 代理连接已建立 [{proxy_ip}] 国家={country_code} 区域={region_name} UA: {user_agent[:30]}...")

        # 创建AWS会话
        session, proxy_info, user_agent = create_boto3_session_with_proxy(access_key, secret_key, proxy_url, user_agent)
        if not session:
            return False, "代理连接失败，无法创建会话", country_code, proxy_ip

        # 配置EC2客户端
        config = Config(user_agent=user_agent, proxies=proxy_info if proxy_info else None)
        ec2_client = session.client('ec2', region_name=region_code, config=config)

        # 获取默认VPC
        vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
        if not vpcs['Vpcs']:
            logger.error(f"{display_key} = 未找到默认VPC")
            return False, "AWS错误：未找到默认VPC", country_code, proxy_ip
        vpc_id = vpcs['Vpcs'][0]['VpcId']

        # 获取子网
        subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        if not subnets['Subnets']:
            logger.error(f"{display_key} = 未找到可用子网")
            return False, "AWS错误：未找到可用子网", country_code, proxy_ip
        subnet_id = random.choice(subnets['Subnets'])['SubnetId']

        # 创建安全组
        sg_name = f'ec2-sg-{random.randint(10000, 99999)}'
        security_group = ec2_client.create_security_group(GroupName=sg_name, Description='Dynamic SG')
        security_group_id = security_group['GroupId']
        ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[{'IpProtocol': '-1', 'FromPort': -1, 'ToPort': -1, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}]
        )

        # 查找Debian AMI
        images = ec2_client.describe_images(
            Owners=['136693071363'],
            Filters=[
                {'Name': 'name', 'Values': ['debian-11-*']},
                {'Name': 'architecture', 'Values': ['x86_64']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'root-device-type', 'Values': ['ebs']},
                {'Name': 'virtualization-type', 'Values': ['hvm']}
            ]
        )
        debian_ami = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId'] if images[
            'Images'] else default_ami

        # 创建块设备映射
        block_device_mappings = []

        # 确定根卷大小和额外卷
        max_volume_size = 16000  # gp2卷最大16TB
        if disk_size <= max_volume_size:
            # 如果总硬盘大小不超过16000GB，全部分配给根卷
            root_volume_size = disk_size
            additional_volumes = None
        else:
            # 如果总硬盘大小超过16000GB，根卷分配16000GB，超出部分分配给额外卷
            root_volume_size = max_volume_size
            additional_size = disk_size - max_volume_size
            additional_volumes = []

            volume_index = 1
            remaining_size = additional_size
            while remaining_size > 0:
                volume_size = min(max_volume_size, remaining_size)
                device_name = f'/dev/xvd{chr(102 + volume_index)}'
                additional_volumes.append((device_name, volume_size))
                remaining_size -= volume_size
                volume_index += 1

        # 添加根卷配置
        block_device_mappings.append({
            'DeviceName': '/dev/xvda',
            'Ebs': {
                'VolumeSize': root_volume_size,
                'VolumeType': 'gp2',
                'DeleteOnTermination': True
            }
        })

        # 添加额外卷配置（如果有）
        if additional_volumes:
            for device, size in additional_volumes:
                block_device_mappings.append({
                    'DeviceName': device,
                    'Ebs': {
                        'VolumeSize': size,
                        'VolumeType': 'gp2',
                        'DeleteOnTermination': True
                    }
                })

        # 准备用户数据和实例参数
        user_data = get_startup_script()
        request_params = generate_random_request_parameters()

        # 设置启动参数
        run_instances_params = {
            'ImageId': debian_ami,
            'InstanceType': request_params['instance_type'],
            'MinCount': 1,
            'MaxCount': 1,
            'SecurityGroupIds': [security_group_id],
            'SubnetId': subnet_id,
            'UserData': user_data,
            'BlockDeviceMappings': block_device_mappings,
            'TagSpecifications': [{'ResourceType': 'instance',
                                   'Tags': request_params['tags'] + [{'Key': 'DiskSize', 'Value': str(disk_size)}]}] if
            request_params['tags'] else [
                {'ResourceType': 'instance', 'Tags': [{'Key': 'DiskSize', 'Value': str(disk_size)}]}]
        }

        # 启动实例
        response = ec2_client.run_instances(**{k: v for k, v in run_instances_params.items() if v is not None})

        # 获取实例ID
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(
            f"{display_key} = Debian 11 EC2实例启动成功，区域: {region_name}，实例ID: {instance_id}，硬盘: {disk_size}GB")

        # 等待实例运行
        waiter = ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])

        # 获取实例详情
        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = instance_info['Reservations'][0]['Instances'][0]
        public_ip = instance.get('PublicIpAddress', 'No IP assigned')
        launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S %Z')

        # 记录实例信息
        fixed_password = "@Zy123456789"
        logger.info(
            f"{display_key} = 实例IP地址: {public_ip}, 用户名: root, 密码: {fixed_password}, 硬盘: {disk_size}GB")

        # 保存启动日志到文件
        with open('开机日志.txt', 'a', encoding='utf-8') as file:
            file.write(
                f"Access Key: {access_key}, Instance ID: {instance_id}, Region: {region_name}, IP: {public_ip}, "
                f"Launch Time: {launch_time}, Country: {country_code}, Username: root, Password: {fixed_password}, "
                f"Disk Size: {disk_size}GB, Proxy: {proxy_ip}\n"
            )
            # 记录卷信息(如果有额外卷)
            if additional_volumes:
                file.write(f"  - 根卷: /dev/xvda ({root_volume_size}GB)\n")
                for idx, (device, size) in enumerate(additional_volumes):
                    mount_point = f"/mnt/data{idx + 1}"
                    file.write(f"  - 额外卷: {device} ({size}GB) (挂载在 {mount_point})\n")

        return True, "实例启动成功", country_code, proxy_ip

    except ClientError as error:
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        logger.error(f"{display_key} = EC2启动失败: {error_code} - {error_message}")
        return False, "代理连接问题" if "RequestTimeout" in error_code or "ConnectionError" in error_code else f"AWS错误: {error_code} - {error_message}", country_code, proxy_ip
    except requests.RequestException as e:
        logger.error(f"{display_key} = 代理连接错误: {str(e)}")
        return False, "代理连接问题", country_code, proxy_ip
    except Exception as e:
        logger.error(f"{display_key} = 处理出错: {str(e)}")
        return False, "代理连接问题" if any(k in str(e).lower() for k in ["proxy", "connection", "timeout",
                                                                          "socket"]) else f"未知错误: {str(e)}", country_code, proxy_ip
    finally:
        socket.socket = original_socket

def process_account(access_key, secret_key, max_retries=3):
        """处理单个账号，包含重试逻辑"""
        global success_counter, failure_counter
        display_key = format_access_key(access_key)
        retry_count = 0
        proxy_ip = "未知"  # 初始化proxy_ip变量

        while retry_count <= max_retries:
            proxy_url, current_country_code = fetch_proxy_from_country(None)  # 强制每次新国家
            logger.info(f"{display_key} = 获取代理: 国家={current_country_code}")

            try:
                success, message, country_code, current_proxy_ip = launch_ec2_instance(access_key, secret_key, proxy_url, current_country_code)
                proxy_ip = current_proxy_ip  # 更新proxy_ip
                if success:
                    with counter_lock:
                        success_counter += 1
                    return True, proxy_ip
                if "代理" in message or "proxy" in message.lower():
                    logger.info(f"{display_key} = 代理问题，准备第 {retry_count + 1} 次重试")
                    retry_count += 1
                    time.sleep(random.uniform(10, 20))
                else:
                    with counter_lock:
                        failure_counter += 1
                    return False, proxy_ip
            except Exception as e:
                logger.error(f"{display_key} = 处理出错: {str(e)}")
                retry_count += 1
                time.sleep(random.uniform(10, 20))

        # 达到最大重试次数
        with counter_lock:
            failure_counter += 1
        logger.error(f"{display_key} = 达到最大重试次数 ({max_retries})")
        return False, proxy_ip

from collections import Counter

def main():
    global selected_region, success_counter, failure_counter, disk_size
    success_counter = failure_counter = 0

    # 创建一个用于存储结果的表格数据
    headers = ["密钥ID", "状态", "代理IP", "处理时间"]
    rows = []

    # 界面显示
    print("\n" + "=" * 50)
    print("      AWS EC2 自动化启动工具 - 高级版")
    print("=" * 50 + "\n")

    # 区域选择部分
    print("可用区域:")
    for key, region in AWS_REGIONS.items():
        print(f"  {key}: {region['name']} ({region['code']})")
    region_choice = input("\n请选择区域 (1-5，默认1): ").strip() or "1"
    selected_region = AWS_REGIONS.get(region_choice)
    if not selected_region:
        logger.error("无效的区域选择")
        return
    print(f"已选择区域: {selected_region['name']} ({selected_region['code']})")
    logger.info(f"已选择区域: {selected_region['name']} ({selected_region['code']})")

    # 硬盘大小输入
    disk_input = input("\n请输入硬盘大小 (GB，最小8GB，直接回车使用默认值): ").strip()
    if not disk_input:
        print(f"使用默认硬盘大小: {disk_size}GB")
        logger.info(f"使用默认硬盘大小: {disk_size}GB")
    else:
        try:
            input_size = int(disk_input)
            if input_size < 8:
                print("硬盘大小不能小于8GB，已设置为默认值8GB")
                disk_size = 8
            else:
                disk_size = input_size
                print(f"硬盘大小设置为: {disk_size}GB")
        except ValueError:
            print(f"输入无效，已设置为默认值{disk_size}GB")

    # 确认开始
    confirm = input("\n确认继续? (y/n，默认y): ").strip().lower() or "y"
    if confirm != 'y':
        print("操作已取消")
        return
    logger.info(f"硬盘大小设置为: {disk_size}GB")

    # 读取AWS密钥
    print("\n正在读取密钥文件...")
    key_pairs = read_aws_keys('key.txt')
    if not key_pairs:
        logger.error("没有可用的AWS密钥")
        print("错误: 没有可用的AWS密钥，请检查key.txt文件")
        return

    print(f"已加载 {len(key_pairs)} 个AWS密钥")
    logger.info(f"加载了 {len(key_pairs)} 个AWS密钥")

    # 顺序处理每个密钥对
    start_time = time.time()
    console = Console()
    console.print("\n[bold cyan]开始批量处理 AWS 密钥...[/bold cyan]\n")

    for idx, (ak, sk) in enumerate(key_pairs, 1):
        display_key = format_access_key(ak)
        key_start_time = time.time()  # 记录每个密钥的开始时间
        proxy_retries = 0
        max_proxy_retries = 3
        success = False
        proxy_ip = "未知"

        while proxy_retries < max_proxy_retries and not success:
            sys.stdout.write(f"\r[第{idx}个] {display_key} - 正在获取代理 (尝试 {proxy_retries + 1}/{max_proxy_retries})...")
            sys.stdout.flush()
            proxy_url, country = fetch_proxy_from_country()

            sys.stdout.write(f"\r[第{idx}个] {display_key} - 测试代理 {country} (尝试 {proxy_retries + 1}/{max_proxy_retries})...")
            sys.stdout.flush()
            user_agent = get_random_user_agent()
            proxy_ok, proxy_msg = test_proxy_connection(proxy_url, user_agent)

            if not proxy_ok:
                sys.stdout.write(f"\r[第{idx}个] {display_key} - 代理失败 ❌ ({proxy_msg})")
                sys.stdout.flush()
                proxy_retries += 1
                if proxy_retries < max_proxy_retries:
                    logger.info(f"{display_key} = 代理失败，准备第 {proxy_retries + 1} 次重试")
                    time.sleep(random.uniform(5, 10))
                continue

            sys.stdout.write(f"\r[第{idx}个] {display_key} - 启动实例中...")
            sys.stdout.flush()

            success, proxy_ip = process_account(ak, sk)  # 使用process_account处理重试逻辑
            key_end_time = time.time()
            processing_time = key_end_time - key_start_time

            if success:
                sys.stdout.write(f"\r[第{idx}个] {display_key} - 启动成功 ✅\n")
                rows.append([display_key, "成功", proxy_ip, f"{processing_time:.1f}s"])
            else:
                sys.stdout.write(f"\r[第{idx}个] {display_key} - 启动失败 ❌\n")
                rows.append([display_key, "失败", proxy_ip, f"{processing_time:.1f}s"])
            sys.stdout.flush()

        # 如果代理重试达到最大次数仍失败，记录失败
        if not success:
            sys.stdout.write(f"\r[第{idx}个] {display_key} - 代理重试达到最大次数，启动失败 ❌\n")
            rows.append([display_key, "失败", proxy_ip, f"{time.time() - key_start_time:.1f}s"])
            with counter_lock:
                failure_counter += 1

        # 每个密钥处理完成后随机延迟
        if idx < len(key_pairs):
            delay_sec = random.uniform(10, 20)
            print(f"等待 {delay_sec:.1f} 秒后继续...")
            time.sleep(delay_sec)

    # 输出统计表格
    total_time = time.time() - start_time
    console.print("\n[bold green]所有密钥处理完成[/bold green]")
    console.print(f"[yellow]总耗时: {total_time:.1f} 秒 | 成功: {success_counter} | 失败: {failure_counter}[/yellow]")



if __name__ == "__main__":
        try:
            main()
        except KeyboardInterrupt:
            print("\n程序被用户中断")
        except Exception as e:
            logger.error(f"程序异常: {str(e)}")
            print(f"\n程序出错: {str(e)}")
        finally:
            print("\n程序已退出")

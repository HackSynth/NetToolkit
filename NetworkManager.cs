using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace NetToolkit
{
    public class NetworkManager
    {
        public async Task<List<NetworkInterfaceInfo>> GetNetworkInterfacesAsync()
        {
            return await Task.Run(() =>
            {
                var interfaces = new List<NetworkInterfaceInfo>();
                
                try
                {
                    var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces()
                        .Where(ni => ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
                                   ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211)
                        .Where(ni => ni.OperationalStatus == OperationalStatus.Up);

                    foreach (var ni in networkInterfaces)
                    {
                        var interfaceInfo = new NetworkInterfaceInfo
                        {
                            Id = ni.Id,
                            Name = ni.Name,
                            Description = ni.Description,
                            Type = ni.NetworkInterfaceType.ToString(),
                            Status = ni.OperationalStatus.ToString()
                        };

                        // 获取IP配置信息
                        var ipProperties = ni.GetIPProperties();
                        var ipv4Properties = ipProperties.GetIPv4Properties();
                        
                        if (ipProperties.UnicastAddresses.Any())
                        {
                            var ipv4Address = ipProperties.UnicastAddresses
                                .FirstOrDefault(ua => ua.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
                            
                            if (ipv4Address != null)
                            {
                                interfaceInfo.IpAddress = ipv4Address.Address.ToString();
                                interfaceInfo.SubnetMask = ipv4Address.IPv4Mask.ToString();
                            }
                        }

                        if (ipProperties.GatewayAddresses.Any())
                        {
                            interfaceInfo.Gateway = ipProperties.GatewayAddresses.First().Address.ToString();
                        }

                        interfaces.Add(interfaceInfo);
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"获取网络接口信息失败: {ex.Message}", ex);
                }

                return interfaces;
            });
        }

        public async Task<NetworkConfiguration> GetCurrentConfigurationAsync(string interfaceId)
        {
            return await Task.Run(() =>
            {
                var config = new NetworkConfiguration();
                
                try
                {
                    // 使用WMI获取详细的网络配置信息
                    var query = $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{interfaceId}'";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        config.IsDhcpEnabled = (bool)(mo["DHCPEnabled"] ?? false);
                        
                        var ipAddresses = mo["IPAddress"] as string[];
                        if (ipAddresses != null && ipAddresses.Length > 0)
                        {
                            config.IpAddress = ipAddresses[0];
                        }

                        var subnetMasks = mo["IPSubnet"] as string[];
                        if (subnetMasks != null && subnetMasks.Length > 0)
                        {
                            config.SubnetMask = subnetMasks[0];
                        }

                        var gateways = mo["DefaultIPGateway"] as string[];
                        if (gateways != null && gateways.Length > 0)
                        {
                            config.Gateway = gateways[0];
                        }

                        var dnsServers = mo["DNSServerSearchOrder"] as string[];
                        if (dnsServers != null && dnsServers.Length > 0)
                        {
                            config.DnsServers = string.Join(",", dnsServers);
                        }

                        break;
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"获取网络配置失败: {ex.Message}", ex);
                }

                return config;
            });
        }

        public async Task ApplyNetworkConfigurationAsync(string interfaceId, NetworkConfiguration config)
        {
            await Task.Run(async () =>
            {
                try
                {
                    // 检查是否为WLAN适配器
                    bool isWlanAdapter = await IsWlanAdapterAsync(interfaceId);
                    
                    if (config.IsDhcpEnabled)
                    {
                        await EnableDhcpAsync(interfaceId, isWlanAdapter);
                    }
                    else
                    {
                        // 设置静态IP前先检测IP冲突
                        await CheckIpConflictAsync(config.IpAddress, interfaceId);
                        SetStaticIp(interfaceId, config);
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"应用网络配置失败: {ex.Message}", ex);
                }
            });
        }

        private async Task CheckIpConflictAsync(string ipAddress, string currentInterfaceId)
        {
            try
            {
                // 1. 检查当前系统中是否已有其他接口使用此IP
                await CheckSystemIpConflictAsync(ipAddress, currentInterfaceId);
                
                // 2. 通过ping检测网络中是否有其他设备使用此IP
                await CheckNetworkIpConflictAsync(ipAddress);
                
                // 3. 通过ARP表检测是否存在冲突
                await CheckArpConflictAsync(ipAddress);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"IP冲突检测失败: {ex.Message}", ex);
            }
        }

        private async Task CheckSystemIpConflictAsync(string targetIp, string currentInterfaceId)
        {
            await Task.Run(() =>
            {
                try
                {
                    var query = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        var settingId = mo["SettingID"]?.ToString();
                        if (settingId == currentInterfaceId) continue; // 跳过当前接口
                        
                        var ipAddresses = mo["IPAddress"] as string[];
                        if (ipAddresses != null)
                        {
                            foreach (var ip in ipAddresses)
                            {
                                if (ip.Equals(targetIp, StringComparison.OrdinalIgnoreCase))
                                {
                                    var description = mo["Description"]?.ToString() ?? "未知接口";
                                    throw new InvalidOperationException($"IP地址 {targetIp} 已被系统中的其他网络接口使用: {description}");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) when (!(ex is InvalidOperationException))
                {
                    throw new InvalidOperationException($"检查系统IP冲突失败: {ex.Message}", ex);
                }
            });
        }

        private async Task CheckNetworkIpConflictAsync(string ipAddress)
        {
            try
            {
                // 使用多次ping检测，提高准确性
                var pingTasks = new List<Task<bool>>();
                
                // 连续ping 3次，超时时间较短
                for (int i = 0; i < 3; i++)
                {
                    pingTasks.Add(TestConnectivityAsync(ipAddress, 1000));
                    if (i < 2) await Task.Delay(500); // 间隔500ms
                }
                
                var results = await Task.WhenAll(pingTasks);
                
                // 如果有任何一次ping成功，说明IP被占用
                if (results.Any(r => r))
                {
                    // 额外验证：尝试获取MAC地址
                    var macAddress = await GetMacAddressByIpAsync(ipAddress);
                    var warningMessage = $"警告：IP地址 {ipAddress} 可能已被网络中的其他设备使用";
                    if (!string.IsNullOrEmpty(macAddress))
                    {
                        warningMessage += $" (MAC: {macAddress})";
                    }
                    
                    throw new InvalidOperationException($"{warningMessage}。继续设置可能导致网络冲突，请选择其他IP地址。");
                }
            }
            catch (Exception ex) when (!(ex is InvalidOperationException))
            {
                // ping失败不一定表示没有冲突，但也不应该阻止配置
                System.Diagnostics.Debug.WriteLine($"网络ping检测失败: {ex.Message}");
            }
        }

        private async Task CheckArpConflictAsync(string ipAddress)
        {
            try
            {
                await Task.Run(async () =>
                {
                    try
                    {
                        // 使用arp命令检查ARP表
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "arp",
                                Arguments = $"-a {ipAddress}",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                CreateNoWindow = true
                            }
                        };
                        
                        process.Start();
                        var output = await process.StandardOutput.ReadToEndAsync();
                        await process.WaitForExitAsync();
                        
                        // 如果ARP表中有该IP的记录，且不是本机MAC地址
                        if (!string.IsNullOrEmpty(output) && output.Contains(ipAddress))
                        {
                            var lines = output.Split('\n');
                            foreach (var line in lines)
                            {
                                if (line.Contains(ipAddress) && line.Contains("-"))
                                {
                                    System.Diagnostics.Debug.WriteLine($"ARP表中发现IP {ipAddress}: {line.Trim()}");
                                    // 这里不直接抛异常，因为ARP表可能有过期记录
                                    break;
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"ARP检测失败: {ex.Message}");
                    }
                });
            }
            catch
            {
                // ARP检测失败不阻止IP设置
            }
        }

        private async Task<string> GetMacAddressByIpAsync(string ipAddress)
        {
            try
            {
                return await Task.Run(async () =>
                {
                    try
                    {
                        var process = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "ping",
                                Arguments = $"-n 1 {ipAddress}",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            }
                        };
                        
                        process.Start();
                        await process.WaitForExitAsync();
                        
                        // 然后查询ARP表获取MAC地址
                        var arpProcess = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = "arp",
                                Arguments = $"-a {ipAddress}",
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true
                            }
                        };
                        
                        arpProcess.Start();
                        var output = await arpProcess.StandardOutput.ReadToEndAsync();
                        await arpProcess.WaitForExitAsync();
                        
                        if (!string.IsNullOrEmpty(output))
                        {
                            var lines = output.Split('\n');
                            foreach (var line in lines)
                            {
                                if (line.Contains(ipAddress))
                                {
                                    var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                    if (parts.Length >= 2)
                                    {
                                        return parts[1]; // MAC地址通常在第二列
                                    }
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"获取MAC地址失败: {ex.Message}");
                    }
                    
                    return "";
                });
            }
            catch
            {
                return "";
            }
        }

        private Task<bool> IsWlanAdapterAsync(string interfaceId)
        {
            return Task.Run(() =>
            {
                try
                {
                    var query = $"SELECT * FROM Win32_NetworkAdapter WHERE GUID = '{interfaceId}'";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        var adapterType = mo["AdapterType"]?.ToString() ?? "";
                        var name = mo["Name"]?.ToString() ?? "";
                        var description = mo["Description"]?.ToString() ?? "";
                        
                        // 检查是否为无线网络适配器
                        return adapterType.ToLower().Contains("wireless") ||
                               adapterType.ToLower().Contains("wifi") ||
                               name.ToLower().Contains("wireless") ||
                               name.ToLower().Contains("wifi") ||
                               description.ToLower().Contains("wireless") ||
                               description.ToLower().Contains("wifi");
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"检查WLAN适配器失败: {ex.Message}");
                }
                
                return false;
            });
        }

        private async Task EnableDhcpAsync(string interfaceId, bool isWlanAdapter)
        {
            try
            {
                if (isWlanAdapter)
                {
                    // WLAN适配器需要特殊处理
                    await EnableDhcpForWlanAsync(interfaceId);
                }
                else
                {
                    // 有线网络适配器也使用异步方法
                    await EnableDhcpForEthernetAsync(interfaceId);
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"启用DHCP操作失败: {ex.Message}", ex);
            }
        }

        private Task EnableDhcpForWlanAsync(string interfaceId)
        {
            return Task.Run(() =>
            {
                try
                {
                    var query = $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{interfaceId}'";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        // 1. 先获取当前IP地址，用于EnableStatic清除网关
                        string[] currentIPs = null;
                        string[] currentMasks = null;
                        try
                        {
                            currentIPs = mo["IPAddress"] as string[];
                            currentMasks = mo["IPSubnet"] as string[];
                            
                            if (currentIPs != null && currentIPs.Length > 0)
                            {
                                System.Diagnostics.Debug.WriteLine($"WLAN适配器: 当前IP: {currentIPs[0]}");
                                
                                // 使用EnableStatic方法并设置网关为相同IP来清除网关
                                var staticParams = mo.GetMethodParameters("EnableStatic");
                                staticParams["IPAddress"] = new string[] { currentIPs[0] };
                                staticParams["SubnetMask"] = new string[] { currentMasks?[0] ?? "255.255.255.0" };

                                var staticResult = mo.InvokeMethod("EnableStatic", staticParams, null);
                                var staticReturnValue = (uint)staticResult["ReturnValue"];

                                // 将gateway设置为当前IP
                                var gatewayParams = mo.GetMethodParameters("SetGateways");
                                gatewayParams["DefaultIPGateway"] = new string[] { currentIPs[0] };
                                var gatewayResult = mo.InvokeMethod("SetGateways", gatewayParams, null);
                                var gatewayReturnValue = (uint)gatewayResult["ReturnValue"];

                                System.Diagnostics.Debug.WriteLine($"WLAN适配器: EnableStatic清除网关，返回值: {gatewayReturnValue}");
                            }
                        }
                        catch (Exception staticEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"WLAN适配器: EnableStatic清除网关失败: {staticEx.Message}");
                        }

                        // 2. 清除DNS设置
                        try
                        {
                            var dnsParams = mo.GetMethodParameters("SetDNSServerSearchOrder");
                            dnsParams["DNSServerSearchOrder"] = null;
                            var dnsResult = mo.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                            var dnsReturnValue = (uint)dnsResult["ReturnValue"];
                            
                            if (dnsReturnValue == 0 || dnsReturnValue == 1)
                            {
                                System.Diagnostics.Debug.WriteLine("WLAN适配器: 已清除DNS设置");
                            }
                        }
                        catch (Exception dnsEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"WLAN适配器: 清除DNS设置失败: {dnsEx.Message}");
                        }

                        // 3. 启用DHCP
                        var dhcpResult = mo.InvokeMethod("EnableDHCP", null);
                        var dhcpReturnValue = (uint)dhcpResult;
                        
                        if (dhcpReturnValue != 0 && dhcpReturnValue != 1)
                        {
                            throw new InvalidOperationException($"启用DHCP失败，错误代码: {dhcpReturnValue}");
                        }
                        
                        System.Diagnostics.Debug.WriteLine("WLAN适配器: 已启用DHCP");

                        // 4. 验证网关清除结果
                        try
                        {
                            // 刷新对象以获取最新状态
                            mo.Get();
                            var currentGateways = mo["DefaultIPGateway"] as string[];
                            
                            if (currentGateways != null && currentGateways.Length > 0)
                            {
                                System.Diagnostics.Debug.WriteLine($"WLAN适配器: 当前网关: {string.Join(", ", currentGateways)}");
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine("WLAN适配器: 网关已完全清除");
                            }
                        }
                        catch (Exception verifyEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"WLAN适配器: 验证网关状态失败: {verifyEx.Message}");
                        }
                        
                        break;
                    }

                    System.Diagnostics.Debug.WriteLine("WLAN适配器已设置为DHCP模式，使用EnableStatic方法清除网关");
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"WLAN适配器设置DHCP模式失败: {ex.Message}", ex);
                }
            });
        }

        private Task EnableDhcpForEthernetAsync(string interfaceId)
        {
            return Task.Run(() =>
            {
                try
                {
                    var query = $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{interfaceId}'";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        // 1. 先获取当前IP地址，用于EnableStatic清除网关
                        string[] currentIPs = null;
                        string[] currentMasks = null;
                        try
                        {
                            currentIPs = mo["IPAddress"] as string[];
                            currentMasks = mo["IPSubnet"] as string[];
                            
                            if (currentIPs != null && currentIPs.Length > 0)
                            {
                                System.Diagnostics.Debug.WriteLine($"当前IP: {currentIPs[0]}");
                                
                                // 使用EnableStatic方法并设置网关为相同IP来清除网关
                                var staticParams = mo.GetMethodParameters("EnableStatic");
                                staticParams["IPAddress"] = new string[] { currentIPs[0] };
                                staticParams["SubnetMask"] = new string[] { currentMasks?[0] ?? "255.255.255.0" };

                                var staticResult = mo.InvokeMethod("EnableStatic", staticParams, null);
                                var staticReturnValue = (uint)staticResult["ReturnValue"];

                                // 将gateway设置为当前IP
                                var gatewayParams = mo.GetMethodParameters("SetGateways");
                                gatewayParams["DefaultIPGateway"] = new string[] { currentIPs[0] };
                                var gatewayResult = mo.InvokeMethod("SetGateways", gatewayParams, null);
                                var gatewayReturnValue = (uint)gatewayResult["ReturnValue"];

                                System.Diagnostics.Debug.WriteLine($"EnableStatic清除网关，返回值: {gatewayReturnValue}");
                            }
                        }
                        catch (Exception staticEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"EnableStatic清除网关失败: {staticEx.Message}");
                        }

                        // 2. 清除DNS设置
                        try
                        {
                            var dnsParams = mo.GetMethodParameters("SetDNSServerSearchOrder");
                            dnsParams["DNSServerSearchOrder"] = null;
                            var dnsResult = mo.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                            var dnsReturnValue = (uint)dnsResult["ReturnValue"];
                            
                            if (dnsReturnValue == 0 || dnsReturnValue == 1)
                            {
                                System.Diagnostics.Debug.WriteLine("已清除DNS设置");
                            }
                        }
                        catch (Exception dnsEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"清除DNS设置失败: {dnsEx.Message}");
                        }

                        // 3. 启用DHCP
                        var dhcpResult = mo.InvokeMethod("EnableDHCP", null);
                        var dhcpReturnValue = (uint)dhcpResult;
                        
                        if (dhcpReturnValue != 0 && dhcpReturnValue != 1)
                        {
                            throw new InvalidOperationException($"启用DHCP失败，错误代码: {dhcpReturnValue}");
                        }
                        
                        System.Diagnostics.Debug.WriteLine("已启用DHCP");

                        // 4. 验证网关清除结果
                        try
                        {
                            // 刷新对象以获取最新状态
                            mo.Get();
                            var currentGateways = mo["DefaultIPGateway"] as string[];
                            
                            if (currentGateways != null && currentGateways.Length > 0)
                            {
                                System.Diagnostics.Debug.WriteLine($"当前网关: {string.Join(", ", currentGateways)}");
                            }
                            else
                            {
                                System.Diagnostics.Debug.WriteLine("网关已完全清除");
                            }
                        }
                        catch (Exception verifyEx)
                        {
                            System.Diagnostics.Debug.WriteLine($"验证网关状态失败: {verifyEx.Message}");
                        }
                        
                        break;
                    }

                    System.Diagnostics.Debug.WriteLine("网络适配器已设置为DHCP模式，使用EnableStatic方法清除网关");
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"设置DHCP模式失败: {ex.Message}", ex);
                }
            });
        }

        private void SetStaticIp(string interfaceId, NetworkConfiguration config)
        {
            try
            {
                var query = $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{interfaceId}'";
                using var searcher = new ManagementObjectSearcher(query);
                using var collection = searcher.Get();
                
                foreach (ManagementObject mo in collection)
                {
                    // 设置静态IP和子网掩码
                    var ipParams = mo.GetMethodParameters("EnableStatic");
                    ipParams["IPAddress"] = new string[] { config.IpAddress };
                    ipParams["SubnetMask"] = new string[] { config.SubnetMask };
                    
                    var ipResult = mo.InvokeMethod("EnableStatic", ipParams, null);
                    var ipReturnValue = (uint)ipResult["ReturnValue"];
                    
                    if (ipReturnValue != 0 && ipReturnValue != 1) // 0=成功, 1=需要重启
                    {
                        throw new InvalidOperationException($"设置IP地址失败，错误代码: {ipReturnValue}");
                    }

                    // 设置默认网关
                    if (!string.IsNullOrEmpty(config.Gateway))
                    {
                        var gatewayParams = mo.GetMethodParameters("SetGateways");
                        gatewayParams["DefaultIPGateway"] = new string[] { config.Gateway };
                        gatewayParams["GatewayCostMetric"] = new int[] { 1 };
                        
                        var gatewayResult = mo.InvokeMethod("SetGateways", gatewayParams, null);
                        var gatewayReturnValue = (uint)gatewayResult["ReturnValue"];
                        
                        if (gatewayReturnValue != 0 && gatewayReturnValue != 1)
                        {
                            throw new InvalidOperationException($"设置默认网关失败，错误代码: {gatewayReturnValue}");
                        }
                    }

                    // 设置DNS服务器
                    if (!string.IsNullOrEmpty(config.DnsServers))
                    {
                        var dnsServers = config.DnsServers.Split(',')
                            .Select(dns => dns.Trim())
                            .Where(dns => !string.IsNullOrEmpty(dns))
                            .ToArray();

                        if (dnsServers.Length > 0)
                        {
                            var dnsParams = mo.GetMethodParameters("SetDNSServerSearchOrder");
                            dnsParams["DNSServerSearchOrder"] = dnsServers;
                            
                            var dnsResult = mo.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                            var dnsReturnValue = (uint)dnsResult["ReturnValue"];
                            
                            if (dnsReturnValue != 0 && dnsReturnValue != 1)
                            {
                                throw new InvalidOperationException($"设置DNS服务器失败，错误代码: {dnsReturnValue}");
                            }
                        }
                    }
                    
                    break;
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"设置静态IP操作失败: {ex.Message}", ex);
            }
        }

        public async Task<bool> TestConnectivityAsync(string ipAddress, int timeout = 3000)
        {
            try
            {
                using var ping = new Ping();
                var reply = await ping.SendPingAsync(ipAddress, timeout);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }

        public async Task FlushDnsAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "cmd.exe",
                            Arguments = "/c ipconfig /flushdns",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true
                        }
                    };
                    
                    process.Start();
                    process.WaitForExit();
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"清除DNS缓存失败: {ex.Message}", ex);
                }
            });
        }

        public async Task<List<string>> GetDhcpLeasesAsync()
        {
            return await Task.Run(() =>
            {
                var leases = new List<string>();
                
                try
                {
                    var query = "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE DHCPEnabled = True";
                    using var searcher = new ManagementObjectSearcher(query);
                    using var collection = searcher.Get();
                    
                    foreach (ManagementObject mo in collection)
                    {
                        var dhcpServer = mo["DHCPServer"]?.ToString();
                        var dhcpLeaseObtained = mo["DHCPLeaseObtained"];
                        var dhcpLeaseExpires = mo["DHCPLeaseExpires"];
                        
                        if (!string.IsNullOrEmpty(dhcpServer))
                        {
                            var leaseInfo = $"DHCP服务器: {dhcpServer}";
                            
                            if (dhcpLeaseObtained != null)
                            {
                                var obtainedTime = ManagementDateTimeConverter.ToDateTime(dhcpLeaseObtained.ToString());
                                leaseInfo += $", 获得时间: {obtainedTime:yyyy-MM-dd HH:mm:ss}";
                            }
                            
                            if (dhcpLeaseExpires != null)
                            {
                                var expiresTime = ManagementDateTimeConverter.ToDateTime(dhcpLeaseExpires.ToString());
                                leaseInfo += $", 过期时间: {expiresTime:yyyy-MM-dd HH:mm:ss}";
                            }
                            
                            leases.Add(leaseInfo);
                        }
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"获取DHCP租约信息失败: {ex.Message}", ex);
                }
                
                return leases;
            });
        }
    }

    public class NetworkInterfaceInfo
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Type { get; set; }
        public string Status { get; set; }
        public string IpAddress { get; set; }
        public string SubnetMask { get; set; }
        public string Gateway { get; set; }
    }

    public class NetworkConfiguration
    {
        public string InterfaceName { get; set; }
        public bool IsDhcpEnabled { get; set; }
        public string IpAddress { get; set; }
        public string SubnetMask { get; set; }
        public string Gateway { get; set; }
        public string DnsServers { get; set; }
    }
}
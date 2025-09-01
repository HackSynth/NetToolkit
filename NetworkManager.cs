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
            await Task.Run(() =>
            {
                try
                {
                    if (config.IsDhcpEnabled)
                    {
                        EnableDhcp(interfaceId);
                    }
                    else
                    {
                        SetStaticIp(interfaceId, config);
                    }
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException($"应用网络配置失败: {ex.Message}", ex);
                }
            });
        }

        private void EnableDhcp(string interfaceId)
        {
            try
            {
                var query = $"SELECT * FROM Win32_NetworkAdapterConfiguration WHERE SettingID = '{interfaceId}'";
                using var searcher = new ManagementObjectSearcher(query);
                using var collection = searcher.Get();
                
                foreach (ManagementObject mo in collection)
                {
                    // 启用DHCP获取IP地址
                    var result = mo.InvokeMethod("EnableDHCP", null);
                    var returnValue = (uint)result;
                    
                    if (returnValue != 0 && returnValue != 1) // 0=成功, 1=需要重启
                    {
                        throw new InvalidOperationException($"启用DHCP失败，错误代码: {returnValue}");
                    }

                    // 清除自定义DNS设置，让系统使用DHCP分配的DNS
                    try
                    {
                        var dnsParams = mo.GetMethodParameters("SetDNSServerSearchOrder");
                        dnsParams["DNSServerSearchOrder"] = null; // 设置为null清除自定义DNS
                        
                        var dnsResult = mo.InvokeMethod("SetDNSServerSearchOrder", dnsParams, null);
                        var dnsReturnValue = (uint)dnsResult["ReturnValue"];
                        
                        // DNS设置失败不应该阻止DHCP启用，只记录警告
                        if (dnsReturnValue != 0 && dnsReturnValue != 1)
                        {
                            System.Diagnostics.Debug.WriteLine($"清除DNS设置时出现警告，错误代码: {dnsReturnValue}");
                        }
                    }
                    catch (Exception dnsEx)
                    {
                        // DNS清除失败不应该影响DHCP启用
                        System.Diagnostics.Debug.WriteLine($"清除DNS设置失败: {dnsEx.Message}");
                    }
                    
                    break;
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"启用DHCP操作失败: {ex.Message}", ex);
            }
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
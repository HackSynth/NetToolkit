using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using MaterialDesignThemes.Wpf;

namespace NetToolkit
{
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        private readonly NetworkManager _networkManager;
        private readonly ObservableCollection<PingResult> _pingResults;
        private readonly CollectionViewSource _pingResultsViewSource;
        private CancellationTokenSource _pingCancellationTokenSource;
        private int _successCount, _failCount, _timeoutCount;

        public MainWindow()
        {
            InitializeComponent();
            _networkManager = new NetworkManager();
            _pingResults = new ObservableCollection<PingResult>();
            
            // 创建CollectionViewSource用于分组
            _pingResultsViewSource = new CollectionViewSource
            {
                Source = _pingResults
            };
            _pingResultsViewSource.GroupDescriptions.Add(new PropertyGroupDescription("Status"));
            
            // 等待UI加载完成后再进行初始化
            Loaded += MainWindow_Loaded;
            DataContext = this;
        }

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                if (PingResultDataGrid != null)
                    PingResultDataGrid.ItemsSource = _pingResultsViewSource.View;
                
                await LoadNetworkInterfacesAsync();
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"窗口加载失败: {ex.Message}");
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private async Task LoadNetworkInterfacesAsync()
        {
            try
            {
                if (NetworkInterfaceComboBox == null) return;
                
                SetStatusMessage("正在加载网络接口...");
                
                var interfaces = await _networkManager.GetNetworkInterfacesAsync();
                NetworkInterfaceComboBox.ItemsSource = interfaces;
                if (interfaces.Any())
                {
                    NetworkInterfaceComboBox.SelectedIndex = 0;
                }

                SetStatusMessage("就绪");
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"加载网络接口失败: {ex.Message}");
                SetStatusMessage("加载网络接口失败");
            }
        }

        private async void NetworkInterfaceComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (NetworkInterfaceComboBox?.SelectedItem is NetworkInterfaceInfo selectedInterface)
            {
                try
                {
                    SetStatusMessage("正在获取网络配置...");
                    var config = await _networkManager.GetCurrentConfigurationAsync(selectedInterface.Id);
                    DisplayCurrentConfiguration(config);
                    SetStatusMessage("就绪");
                }
                catch (Exception ex)
                {
                    ShowErrorMessage($"获取网络配置失败: {ex.Message}");
                    SetStatusMessage("获取网络配置失败");
                }
            }
        }

        private void DisplayCurrentConfiguration(NetworkConfiguration config)
        {
            if (CurrentConfigText == null) return;

            try
            {
                if (config.IsDhcpEnabled)
                {
                    CurrentConfigText.Text = $"当前配置: DHCP自动获取\nIP地址: {config.IpAddress ?? "未分配"}\n子网掩码: {config.SubnetMask ?? "未设置"}\n默认网关: {config.Gateway ?? "未设置"}\nDNS服务器: {config.DnsServers ?? "未设置"}";
                    if (DhcpRadioButton != null)
                        DhcpRadioButton.IsChecked = true;
                }
                else
                {
                    CurrentConfigText.Text = $"当前配置: 静态IP\nIP地址: {config.IpAddress ?? "未设置"}\n子网掩码: {config.SubnetMask ?? "未设置"}\n默认网关: {config.Gateway ?? "未设置"}\nDNS服务器: {config.DnsServers ?? "未设置"}";
                    if (StaticRadioButton != null)
                        StaticRadioButton.IsChecked = true;
                        
                    if (IpAddressTextBox != null)
                        IpAddressTextBox.Text = config.IpAddress ?? "";
                    if (SubnetMaskTextBox != null)
                        SubnetMaskTextBox.Text = config.SubnetMask ?? "";
                    if (GatewayTextBox != null)
                        GatewayTextBox.Text = config.Gateway ?? "";
                    if (DnsTextBox != null)
                        DnsTextBox.Text = config.DnsServers ?? "";
                }
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"显示配置信息失败: {ex.Message}");
            }
        }

        private void DhcpRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            if (StaticConfigGrid != null)
                StaticConfigGrid.IsEnabled = false;
        }

        private void StaticRadioButton_Checked(object sender, RoutedEventArgs e)
        {
            if (StaticConfigGrid != null)
                StaticConfigGrid.IsEnabled = true;
        }

        private async void ApplyConfigButton_Click(object sender, RoutedEventArgs e)
        {
            if (NetworkInterfaceComboBox?.SelectedItem is not NetworkInterfaceInfo selectedInterface)
            {
                ShowErrorMessage("请选择一个网络接口");
                return;
            }

            try
            {
                if (ApplyConfigButton != null)
                    ApplyConfigButton.IsEnabled = false;
                    
                SetStatusMessage("正在应用网络配置...");

                var config = new NetworkConfiguration
                {
                    InterfaceName = selectedInterface.Name,
                    IsDhcpEnabled = DhcpRadioButton?.IsChecked ?? false
                };

                if (StaticRadioButton?.IsChecked ?? false)
                {
                    if (string.IsNullOrWhiteSpace(IpAddressTextBox?.Text) ||
                        string.IsNullOrWhiteSpace(SubnetMaskTextBox?.Text))
                    {
                        ShowErrorMessage("请填写完整的IP地址和子网掩码");
                        return;
                    }

                    config.IpAddress = IpAddressTextBox.Text.Trim();
                    config.SubnetMask = SubnetMaskTextBox.Text.Trim();
                    config.Gateway = GatewayTextBox?.Text?.Trim() ?? "";
                    config.DnsServers = DnsTextBox?.Text?.Trim() ?? "";

                    if (!IsValidIpAddress(config.IpAddress))
                    {
                        ShowErrorMessage("IP地址格式不正确");
                        return;
                    }

                    if (!IsValidIpAddress(config.SubnetMask))
                    {
                        ShowErrorMessage("子网掩码格式不正确");
                        return;
                    }

                    if (!string.IsNullOrEmpty(config.Gateway) && !IsValidIpAddress(config.Gateway))
                    {
                        ShowErrorMessage("默认网关格式不正确");
                        return;
                    }

                    // 静态IP设置前的额外状态提示
                    SetStatusMessage("正在检测IP冲突...");
                }

                await _networkManager.ApplyNetworkConfigurationAsync(selectedInterface.Id, config);
                
                ShowSuccessMessage("网络配置已成功应用！请稍等片刻让配置生效。");
                SetStatusMessage("网络配置应用成功");
                
                // 刷新当前配置显示
                await Task.Delay(2000);
                var newConfig = await _networkManager.GetCurrentConfigurationAsync(selectedInterface.Id);
                DisplayCurrentConfiguration(newConfig);
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"应用网络配置失败: {ex.Message}");
                SetStatusMessage("配置应用失败");
            }
            finally
            {
                if (ApplyConfigButton != null)
                    ApplyConfigButton.IsEnabled = true;
            }
        }

        private void ResetConfigButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                IpAddressTextBox?.Clear();
                SubnetMaskTextBox?.Clear();
                GatewayTextBox?.Clear();
                DnsTextBox?.Clear();
                if (DhcpRadioButton != null)
                    DhcpRadioButton.IsChecked = true;
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"重置配置失败: {ex.Message}");
            }
        }

        private async void RefreshInterfaces_Click(object sender, RoutedEventArgs e)
        {
            await LoadNetworkInterfacesAsync();
        }

        private async void StartPingButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(IpRangeTextBox?.Text))
            {
                ShowErrorMessage("请输入要ping的IP地址或IP地址范围");
                return;
            }

            if (!int.TryParse(TimeoutTextBox?.Text, out int timeout) || timeout <= 0)
            {
                ShowErrorMessage("请输入有效的超时时间");
                return;
            }

            try
            {
                _pingCancellationTokenSource = new CancellationTokenSource();
                
                if (StartPingButton != null)
                    StartPingButton.IsEnabled = false;
                if (StopPingButton != null)
                    StopPingButton.IsEnabled = true;
                if (PingProgressBar != null)
                    PingProgressBar.Visibility = Visibility.Visible;
                    
                SetStatusMessage("正在ping...");

                ResetCounters();
                
                var ipAddresses = ParseIpAddresses(IpRangeTextBox.Text);
                if (PingProgressBar != null)
                {
                    PingProgressBar.Maximum = ipAddresses.Count;
                    PingProgressBar.Value = 0;
                }

                await PingIpAddressesAsync(ipAddresses, timeout, _pingCancellationTokenSource.Token);
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"Ping操作失败: {ex.Message}");
            }
            finally
            {
                if (StartPingButton != null)
                    StartPingButton.IsEnabled = true;
                if (StopPingButton != null)
                    StopPingButton.IsEnabled = false;
                if (PingProgressBar != null)
                    PingProgressBar.Visibility = Visibility.Collapsed;
                    
                SetStatusMessage("Ping操作完成");
            }
        }

        private void StopPingButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _pingCancellationTokenSource?.Cancel();
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"停止Ping操作失败: {ex.Message}");
            }
        }

        private void ClearResultsButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _pingResults.Clear();
                ResetCounters();
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"清空结果失败: {ex.Message}");
            }
        }

        private async Task PingIpAddressesAsync(List<string> ipAddresses, int timeout, CancellationToken cancellationToken)
        {
            // 根据IP数量和系统性能动态调整并发数
            var processorCount = Environment.ProcessorCount;
            var baseThreads = Math.Min(ipAddresses.Count, processorCount * 8); // 基于处理器核心数的8倍
            var maxConcurrency = Math.Min(Math.Max(baseThreads, 32), 128); // 最小32，最大128线程
            var semaphore = new SemaphoreSlim(maxConcurrency);
            
            var completedCount = 0;
            var lockObject = new object();
            var allResults = new List<PingResult>();

            var tasks = ipAddresses.Select(async ip =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var result = await PingSingleAddressAsync(ip, timeout, cancellationToken);
                    
                    // 收集所有结果，稍后统一排序
                    lock (allResults)
                    {
                        allResults.Add(result);
                    }
                    
                    // 更新进度条和计数器
                    _ = Application.Current.Dispatcher.BeginInvoke(new Action(() =>
                    {
                        try
                        {
                            UpdateCounters(result);
                            
                            lock (lockObject)
                            {
                                completedCount++;
                                if (PingProgressBar != null)
                                    PingProgressBar.Value = completedCount;
                            }
                        }
                        catch (Exception ex)
                        {
                            SetStatusMessage($"更新结果失败: {ex.Message}");
                        }
                    }), System.Windows.Threading.DispatcherPriority.Background);
                    
                    return result;
                }
                finally
                {
                    semaphore.Release();
                }
            }).ToArray(); // 转换为数组避免多次枚举

            try
            {
                // 使用ConfigureAwait(false)避免死锁，提高性能
                await Task.WhenAll(tasks).ConfigureAwait(false);
                
                // 所有ping完成后，对结果进行排序并添加到UI
                Application.Current.Dispatcher.Invoke(() =>
                {
                    try
                    {
                        // 按照状态优先级和IP地址排序
                        var sortedResults = SortPingResults(allResults);
                        
                        // 清空现有结果并添加排序后的结果
                        _pingResults.Clear();
                        foreach (var result in sortedResults)
                        {
                            _pingResults.Add(result);
                        }
                        
                        // 刷新分组视图
                        _pingResultsViewSource.View.Refresh();
                        
                        SetStatusMessage($"Ping操作完成，共处理{ipAddresses.Count}个IP地址");
                    }
                    catch (Exception ex)
                    {
                        SetStatusMessage($"排序结果失败: {ex.Message}");
                    }
                });
            }
            catch (OperationCanceledException)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // 即使取消也要显示已完成的排序结果
                    try
                    {
                        var sortedResults = SortPingResults(allResults);
                        _pingResults.Clear();
                        foreach (var result in sortedResults)
                        {
                            _pingResults.Add(result);
                        }
                        // 刷新分组视图
                        _pingResultsViewSource.View.Refresh();
                    }
                    catch { }
                    
                    SetStatusMessage($"Ping操作已取消，已完成{completedCount}/{ipAddresses.Count}个IP地址");
                });
            }
            catch (Exception ex)
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    ShowErrorMessage($"批量Ping失败: {ex.Message}");
                    SetStatusMessage("批量Ping操作失败");
                });
            }
            finally
            {
                semaphore?.Dispose();
            }
        }

        private List<PingResult> SortPingResults(List<PingResult> results)
        {
            try
            {
                // 按照状态优先级分组，然后在每个组内按IP地址排序
                return results.OrderBy(r => GetStatusPriority(r.Status))
                            .ThenBy(r => ParseIpAddressForSorting(r.IpAddress))
                            .ToList();
            }
            catch (Exception ex)
            {
                SetStatusMessage($"排序失败，使用原始顺序: {ex.Message}");
                return results;
            }
        }

        private int GetStatusPriority(string status)
        {
            return status switch
            {
                "成功" => 1,
                "失败" => 2,
                "超时" => 3,
                "错误" => 4,
                "已取消" => 5,
                _ => 6
            };
        }

        private uint ParseIpAddressForSorting(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var bytes = ip.GetAddressBytes();
                    return BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
                }
            }
            catch
            {
                // 如果解析失败，返回最大值，使其排在最后
            }
            return uint.MaxValue;
        }

        private async Task<PingResult> PingSingleAddressAsync(string ipAddress, int timeout, CancellationToken cancellationToken)
        {
            var result = new PingResult
            {
                IpAddress = ipAddress,
                TestTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
            };

            try
            {
                // 检查取消请求，避免不必要的网络操作
                cancellationToken.ThrowIfCancellationRequested();

                // 使用using确保资源正确释放
                using var ping = new Ping();
                
                // 设置ping选项以提高性能
                var buffer = new byte[32]; // 标准ping包大小
                var options = new PingOptions(64, true); // TTL=64，不允许分片
                
                // 异步ping操作，传入取消令牌
                var reply = await ping.SendPingAsync(ipAddress, timeout, buffer, options);
                
                // 再次检查取消请求
                cancellationToken.ThrowIfCancellationRequested();

                switch (reply.Status)
                {
                    case IPStatus.Success:
                        result.Status = "成功";
                        result.ResponseTime = reply.RoundtripTime;
                        result.Notes = $"TTL={reply.Options?.Ttl ?? 0}";
                        break;
                    case IPStatus.TimedOut:
                        result.Status = "超时";
                        result.Notes = $"请求超时 (>{timeout}ms)";
                        break;
                    case IPStatus.DestinationHostUnreachable:
                        result.Status = "失败";
                        result.Notes = "目标主机不可达";
                        break;
                    case IPStatus.DestinationNetworkUnreachable:
                        result.Status = "失败";
                        result.Notes = "目标网络不可达";
                        break;
                    case IPStatus.BadDestination:
                        result.Status = "失败";
                        result.Notes = "无效的目标地址";
                        break;
                    default:
                        result.Status = "失败";
                        result.Notes = reply.Status.ToString();
                        break;
                }
            }
            catch (OperationCanceledException)
            {
                result.Status = "已取消";
                result.Notes = "操作被取消";
            }
            catch (PingException pingEx)
            {
                result.Status = "错误";
                result.Notes = $"Ping错误: {(pingEx.Message.Length > 30 ? pingEx.Message.Substring(0, 30) + "..." : pingEx.Message)}";
            }
            catch (ArgumentException argEx)
            {
                result.Status = "错误";
                result.Notes = $"参数错误: {argEx.Message}";
            }
            catch (ObjectDisposedException)
            {
                result.Status = "已取消";
                result.Notes = "操作被取消";
            }
            catch (Exception ex)
            {
                result.Status = "错误";
                result.Notes = ex.Message.Length > 40 ? ex.Message.Substring(0, 40) + "..." : ex.Message;
            }

            return result;
        }

        private List<string> ParseIpAddresses(string input)
        {
            var ipAddresses = new List<string>();
            
            try
            {
                if (input.Contains("/"))
                {
                    // CIDR格式: 172.10.20.1/24
                    var parts = input.Split('/');
                    if (parts.Length == 2)
                    {
                        var networkIp = parts[0].Trim();
                        var cidrString = parts[1].Trim();
                        
                        if (IPAddress.TryParse(networkIp, out var networkAddr) && 
                            int.TryParse(cidrString, out var cidr) && 
                            cidr >= 0 && cidr <= 32)
                        {
                            var networkBytes = networkAddr.GetAddressBytes();
                            var networkInt = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);
                            
                            // 计算子网掩码
                            var hostBits = 32 - cidr;
                            var hostCount = (uint)Math.Pow(2, hostBits);
                            
                            // 限制生成的IP数量，避免过多IP
                            if (hostCount > 1024)
                            {
                                throw new ArgumentException($"网段过大（/{cidr}），请使用更小的网段（最多1024个IP地址）");
                            }
                            
                            // 计算网络地址（去掉主机位）
                            var subnetMask = 0xFFFFFFFF << hostBits;
                            var actualNetworkInt = networkInt & subnetMask;
                            
                            // 生成网段内的所有IP地址
                            for (uint i = 1; i < hostCount - 1; i++) // 跳过网络地址和广播地址
                            {
                                var ipInt = actualNetworkInt + i;
                                var bytes = BitConverter.GetBytes(ipInt).Reverse().ToArray();
                                var ip = new IPAddress(bytes);
                                ipAddresses.Add(ip.ToString());
                            }
                        }
                        else
                        {
                            throw new ArgumentException("CIDR格式不正确，请使用格式：IP地址/子网位数（如：172.10.20.1/24）");
                        }
                    }
                }
                else if (input.Contains("-"))
                {
                    // IP范围格式: 192.168.1.1-192.168.1.100
                    var parts = input.Split('-');
                    if (parts.Length == 2)
                    {
                        var startIp = parts[0].Trim();
                        var endIp = parts[1].Trim();
                        
                        if (IPAddress.TryParse(startIp, out var startAddr) && 
                            IPAddress.TryParse(endIp, out var endAddr))
                        {
                            var startBytes = startAddr.GetAddressBytes();
                            var endBytes = endAddr.GetAddressBytes();
                            
                            var startInt = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
                            var endInt = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);
                            
                            // 限制IP范围大小，避免生成过多IP
                            if (endInt - startInt > 1000)
                            {
                                throw new ArgumentException("IP地址范围过大，请限制在1000个以内");
                            }
                            
                            for (uint i = startInt; i <= endInt; i++)
                            {
                                var bytes = BitConverter.GetBytes(i).Reverse().ToArray();
                                var ip = new IPAddress(bytes);
                                ipAddresses.Add(ip.ToString());
                            }
                        }
                    }
                }
                else if (input.Contains(","))
                {
                    // 逗号分隔格式: 192.168.1.1,192.168.1.2,192.168.1.3
                    var addresses = input.Split(',');
                    foreach (var addr in addresses)
                    {
                        var trimmedAddr = addr.Trim();
                        if (IsValidIpAddress(trimmedAddr))
                        {
                            ipAddresses.Add(trimmedAddr);
                        }
                    }
                }
                else
                {
                    // 单个IP地址
                    var trimmedInput = input.Trim();
                    if (IsValidIpAddress(trimmedInput))
                    {
                        ipAddresses.Add(trimmedInput);
                    }
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException($"解析IP地址失败: {ex.Message}", ex);
            }

            if (!ipAddresses.Any())
            {
                throw new ArgumentException("未找到有效的IP地址");
            }

            return ipAddresses;
        }

        private bool IsValidIpAddress(string ipAddress)
        {
            return !string.IsNullOrWhiteSpace(ipAddress) && IPAddress.TryParse(ipAddress, out _);
        }

        private void ResetCounters()
        {
            _successCount = _failCount = _timeoutCount = 0;
            UpdateCounterDisplay();
        }

        private void UpdateCounters(PingResult result)
        {
            try
            {
                switch (result.Status)
                {
                    case "成功":
                        _successCount++;
                        break;
                    case "超时":
                        _timeoutCount++;
                        break;
                    case "失败":
                    case "错误":
                        _failCount++;
                        break;
                }
                UpdateCounterDisplay();
            }
            catch (Exception ex)
            {
                ShowErrorMessage($"更新计数器失败: {ex.Message}");
            }
        }

        private void UpdateCounterDisplay()
        {
            try
            {
                if (SuccessCountText != null)
                    SuccessCountText.Text = _successCount.ToString();
                if (FailCountText != null)
                    FailCountText.Text = _failCount.ToString();
                if (TimeoutCountText != null)
                    TimeoutCountText.Text = _timeoutCount.ToString();
            }
            catch (Exception ex)
            {
                // 避免在UI更新中再次显示错误对话框
                SetStatusMessage($"更新显示失败: {ex.Message}");
            }
        }

        private void SetStatusMessage(string message)
        {
            try
            {
                if (StatusText != null)
                    StatusText.Text = message;
            }
            catch
            {
                // 忽略状态更新错误
            }
        }

        private void ShowErrorMessage(string message)
        {
            try
            {
                MessageBox.Show(message, "错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch
            {
                // 如果连消息框都无法显示，则忽略
            }
        }

        private void ShowSuccessMessage(string message)
        {
            try
            {
                MessageBox.Show(message, "成功", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch
            {
                // 如果连消息框都无法显示，则忽略
            }
        }

        private void AboutButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                MessageBox.Show("网络工具包 v1.1\n\n功能:\n• 静态IP地址设置\n• 批量Ping网络测试\n  - 支持单个IP\n  - 支持IP范围 (192.168.1.1-192.168.1.100)\n  - 支持网段CIDR (172.10.20.1/24)\n  - 支持逗号分隔列表\n\n特性:\n• Material Design界面\n• 异步操作支持\n• 完整的异常处理\n\n开发: NetToolkit", 
                              "关于", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                SetStatusMessage($"显示关于信息失败: {ex.Message}");
            }
        }
    }

    public class PingResult
    {
        public string IpAddress { get; set; } = "";
        public string Status { get; set; } = "";
        public long ResponseTime { get; set; } = 0;
        public string TestTime { get; set; } = "";
        public string Notes { get; set; } = "";
    }
}
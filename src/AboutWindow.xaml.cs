using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using iNKORE.UI.WPF.Modern.Controls;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class AboutWindow : Window
    {
        private static bool? isSuccessful = null;
        public AboutWindow()
        {
            InitializeComponent();
            if (Convert.ToInt32(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool").GetValue("TopMost")) == 1)
                this.Topmost = true;
            if (version.Foreground == Brushes.Red)
            {
                license.Content = "Orange Group Confidential";
                internalBuildText.Visibility = Visibility.Visible;
                internalBuildText2.Visibility = Visibility.Visible;
                internalBuildText3.Visibility = Visibility.Visible;
                internalBuildText4.Visibility = Visibility.Visible;
            } else {}

            Task.Run(() =>
            {
                try
                {
                    ServicePointManager.Expect100Continue = true;
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    System.Net.WebClient wc = new System.Net.WebClient();
                    string raw = System.Text.Encoding.UTF8.GetString(wc.DownloadData("http://raw.githubusercontent.com/orangegrouptech/Windows-Malware-Effects-Remediation-Tool/main/version.txt"));
                    Version rawversion = new Version();
                    var version = Assembly.GetExecutingAssembly().GetName().Version;
                    if (rawversion > version)
                    {
                        downloadUpdatesButton.Visibility = Visibility.Visible;
                    }
                }
                catch
                {
                    isSuccessful = false;
                }
            });
        }

        private void closeButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void downloadUpdatesButton_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("https://github.com/orangegrouptech/Windows-Malware-Effects-Remediation-Tool/releases/latest");
        }

        private async Task Delay(int howlong)
        {
            await Task.Delay(howlong);
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            if(isSuccessful == false)
            {
                await Delay(100);
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                dialog.Content = "There was an error checking for updates. Maybe see if you're connected to the Internet or try whitelisting github.com and githubusercontent.com on your firewall.";
                dialog.PrimaryButtonText = "OK";
                dialog.DefaultButton = ContentDialogButton.Primary;
                await dialog.ShowAsync();
            }

            RegistryKey topmost = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            try
            {
                if (Convert.ToInt32(topmost.GetValue("TopMost")) == 1)
                {
                    this.Topmost = true;
                }
            }
            catch { }
        }
    }
}

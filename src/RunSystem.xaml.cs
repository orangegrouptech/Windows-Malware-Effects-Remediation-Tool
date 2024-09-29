using iNKORE.UI.WPF.Modern.Controls;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Management.Instrumentation;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using static Windows_Malware_Effects_Remediation_Tool.WindowsAPIMethods;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for RunElevated.xaml
    /// </summary>
    public partial class RunSystem : Window
    {
        public RunSystem()
        {
            InitializeComponent();

            PopulateDropdown();
            if (Convert.ToInt32(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool").GetValue("TopMost")) == 1)
                this.Topmost = true;
            runTextBox.Focus();
        }

        private void PopulateDropdown()
        {
            RegistryKey recentRuns = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU");

            foreach (string key in recentRuns.GetValueNames())
            {
                if (key == "MRUList") continue;
                string value = recentRuns.GetValue(key).ToString();
                if (value.EndsWith(@"\1")) value = value.Replace(@"\1", "");
                runTextBox.Items.Insert(0, value);
            }
        }

        private void cancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private static SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();

        private async void okButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                runTextBox.IsEnabled = false;
                okButton.IsEnabled = false;
                cancelButton.IsEnabled = false;

                // REFERENCES:
                // https://github.com/mbcdev/RunAsTrustedInstaller/
                // https://github.com/valnoxy/TIelevated

                await Task.Run(() =>
                {
                    Process.EnterDebugMode();

                    // 1. Impersonate as SYSTEM for myself
                    // Get the Winlogon PID
                    uint winlogonPID = ReturnProcessID(@"C:\Windows\System32\winlogon.exe");
                    if (winlogonPID == 0) throw new Exception("Unable to retrieve the Winlogon Process ID.");

                    // Get the SYSTEM token by duplicating Winlogon's access tokenb
                    IntPtr systemToken = DuplicateAccessToken(winlogonPID);

                    // Impersonate the token
                    ImpersonateLoggedOnUser(systemToken);
                    CloseHandle(systemToken);

                    // ------------------------------------------------------------------------------------------------------------------------------------------------------------
                    // 2. Run the target process under TrustedInstaller

                    // Start the TrustedInstaller service
                    ProcessStartInfo startTrustedInstaller = new ProcessStartInfo()
                    {
                        FileName = "net.exe",
                        Arguments = "start TrustedInstaller",
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                    };
                    Process.Start(startTrustedInstaller).WaitForExit();

                    // Get the TrustedInstaller PID
                    uint trustedInstallerPID = ReturnProcessID(@"C:\Windows\servicing\TrustedInstaller.exe");

                    // Get the TrustedInstaller token
                    IntPtr trustedInstallerToken = DuplicateAccessToken(trustedInstallerPID);

                    // Creation flags
                    uint creationFlags = (CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | NORMAL_PRIORITY_CLASS);

                    // Create environment block
                    CreateEnvironmentBlock(out IntPtr environmentBlock, trustedInstallerToken, false);

                    // Startup info
                    STARTUPINFO startupInfo = new STARTUPINFO();
                    startupInfo.cb = Marshal.SizeOf(startupInfo);
                    startupInfo.lpDesktop = @"WinSta0\Default";

                    string processToStart = "";

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        processToStart = runTextBox.Text;
                    });

                    // Start the process with the duplicated token
                    CreateProcessWithTokenW(
                        trustedInstallerToken, // Our TrustedInstaller token
                        1, // Logon as profile
                        $@"{Environment.GetFolderPath(Environment.SpecialFolder.System)}\cmd.exe", // The process to start
                        $@"/c ""{processToStart}""", // Command line arguments
                        creationFlags, // Creation flags
                        environmentBlock, // Environment
                        null, // Working directory of the file we're running
                        ref startupInfo,
                        out PROCESS_INFORMATION processInformation
                    );

                    /*CreateProcessAsUserW(trustedInstallerToken, processToStart, null, ref securityAttributes, ref securityAttributes,
                            false, creationFlags, environmentBlock, workingDirectory, ref startupInfo, out processInformation);*/

                    RevertToSelf();
                });

                await Task.Delay(1000);
                this.Close();
            }
            catch
            {
                ContentDialog contentDialog = new ContentDialog();
                contentDialog.Title = "Error";
                contentDialog.Content = $@"There was an error starting the process ""{runTextBox.Text}"". Make sure you typed the name correctly and try again.";
                contentDialog.PrimaryButtonText = "OK";
                contentDialog.DefaultButton = ContentDialogButton.Primary;
                await contentDialog.ShowAsync();

                runTextBox.IsEnabled = true;
                okButton.IsEnabled = true;
                cancelButton.IsEnabled = true;
            }
        }

        private IntPtr DuplicateAccessToken(uint processID)
        {
            // Retrieve the token
            var processHandle = OpenProcess((uint)OPEN_PROCESS_TOKEN.PROCESS_QUERY_INFORMATION, false, processID);
            OpenProcessToken(
                processHandle,
                (uint)OPEN_PROCESS_TOKEN.TOKEN_QUERY | (uint)OPEN_PROCESS_TOKEN.TOKEN_DUPLICATE,
                out IntPtr processToken
            );

            // Duplicate the token
            DuplicateTokenEx(
                processToken,
            (uint)TOKEN_ALL_ACCESS,
                ref securityAttributes,
                SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                TOKEN_TYPE.TokenImpersonation,
                out IntPtr duplicatedToken
            );

            return duplicatedToken;
        }

        private uint ReturnProcessID(string pathToExecutable)
        {
            ProcessStartInfo powershell = new ProcessStartInfo()
            {
                FileName = "powershell.exe",
                Arguments = @"-c (Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -eq '" + pathToExecutable + "'}).ProcessId",
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardOutput = true,
                UseShellExecute = false
            };
            return Convert.ToUInt32(Process.Start(powershell).StandardOutput.ReadToEnd());
        }

        private async Task Delay(int howlong)
        {
            await Task.Delay(howlong);
        }

        private void Window_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Return)
            {
                if (okButton.IsEnabled == true)
                {
                    okButton_Click(sender, e);
                }
                else { }
            }
        }

        private void browseButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "Executable files (*.exe)|*.exe|Batch files (*.bat)|*.bat|All files (*.*)|*.*";
            openFileDialog.DefaultExt = ".exe";
            openFileDialog.Title = "Select a file to run";
            if (openFileDialog.ShowDialog() == true) runTextBox.Text = openFileDialog.FileName;
        }
    }
}

using iNKORE.UI.WPF.Modern;
using iNKORE.UI.WPF.Modern.Controls;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Threading.Tasks;
using System.Windows;
using static Windows_Malware_Effects_Remediation_Tool.RepairClasses;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            // Check for administrative privileges
            WindowsPrincipal pricipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            bool hasAdministrativeRight = pricipal.IsInRole(WindowsBuiltInRole.Administrator);
            if (!hasAdministrativeRight)
            {
                this.Hide();
                string fileName = Assembly.GetExecutingAssembly().Location;
                ProcessStartInfo processInfo = new ProcessStartInfo();
                processInfo.Verb = "runas";
                processInfo.FileName = fileName;

                try
                {
                    Process.Start(processInfo);
                    Environment.Exit(0);
                }
                catch
                {
                    iNKORE.UI.WPF.Modern.Controls.MessageBox.Show("The Windows Malware Effects Remediation Tool requires administrative privileges to continue.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    Environment.Exit(0);
                }

            }
            else
            {
                InitializeComponent();
                RegistryKey checkdarklightmode = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool");
                if (checkdarklightmode.GetValue("DarkMode") == null)
                {
                    systemSettingMenuItem.IsChecked = true;
                    lightDarkButton.IsEnabled = false;
                }
                else
                if ((int)checkdarklightmode.GetValue("DarkMode") == 1)
                {
                    ThemeManager.Current.ApplicationTheme = ApplicationTheme.Dark;
                }
                else if ((int)checkdarklightmode.GetValue("DarkMode") == 0)
                {
                    ThemeManager.Current.ApplicationTheme = ApplicationTheme.Light;
                }
            }
        }
        private async Task Delay(int howlong)
        {
            await Task.Delay(howlong);
        }

        private void aboutButton_Click(object sender, RoutedEventArgs e)
        {

            AboutWindow aboutWindow = new AboutWindow();
            aboutWindow.ShowDialog();

        }

        private RepairClasses repairClasses = new RepairClasses();

        // Initialise HKLM and HKCU paths
        private RegistryKey hklmSoftwarePath = Registry.LocalMachine.OpenSubKey("SOFTWARE");
        private RegistryKey hklmSystemPath = Registry.LocalMachine.OpenSubKey("SYSTEM");
        private RegistryKey hkcuPath = Registry.CurrentUser;

        private string mountPoint;
        private string username;

        private async void ApplyFix_Handler(string name)
        {
            try
            {
                var fixDetails = repairClasses.fixInformation.Find(x => x.Name == name);

                var fixType = fixDetails.Type;
                var path = fixDetails.Path;
                var key = fixDetails.Key;
                var value = fixDetails.Value;
                var nullable = fixDetails.Nullable;

                bool requireRestart = false;

                for (int i = 0; i < fixType.Count; i++)
                {
                    // If the fix involves the Registry
                    if (fixType[i] == FixType.Registry)
                    {
                        // Determine Registry hive
                        RegistryKey registryKey;
                        if (path[i].Contains(@"HKEY_LOCAL_MACHINE\SOFTWARE"))
                        {
                            registryKey = hklmSoftwarePath.OpenSubKey(path[i].Replace(@"HKEY_LOCAL_MACHINE\SOFTWARE\", ""), true);
                        }
                        else if (path[i].Contains(@"HKEY_LOCAL_MACHINE\SYSTEM"))
                        {
                            registryKey = hklmSystemPath.OpenSubKey(path[i].Replace(@"HKEY_LOCAL_MACHINE\SYSTEM\", ""), true);
                        }
                        else if (path[i].Contains("HKEY_CURRENT_USER"))
                        {
                            registryKey = hkcuPath.OpenSubKey(path[i].Replace(@"HKEY_CURRENT_USER\", ""), true);
                        }
                        else
                        {
                            throw new Exception($@"The fix ""{name}"" was not configured correctly in RepairClasses: Invalid hive in Path (Registry)");
                        }

                        // Perform the fix
                        if (nullable[i] == true)
                        {
                            registryKey.DeleteValue(key[i]);
                        }
                        else
                        {
                            // Convert value to integer if it is an integer
                            int valueInt;
                            if (int.TryParse(value[i], out valueInt))
                            {
                                registryKey.SetValue(key[i], valueInt);
                            }
                            else
                            {
                                registryKey.SetValue(key[i], value[i]);
                            }
                        }

                        registryKey.Dispose();
                    }
                    // If the fix involves files
                    else
                    {
                        string pathToFile;
                        if (separateDriveCheckBox.IsChecked == true)
                        {
                            if (path[i].Contains("%windir%")) pathToFile = path[i].Replace(@"%windir%", mountPoint + @"\Windows");

                            else if (path[i].Contains("%userprofile%")) pathToFile = path[i].Replace(@"%userprofile%", mountPoint + @"\Users\" + username);

                            else if (path[i].Contains("%appdata%")) pathToFile = path[i].Replace(@"%appdata%", mountPoint + @"\Users\" + username + @"\AppData\Roaming");

                            else if (path[i].Contains("%localappdata%")) pathToFile = path[i].Replace(@"%localappdata%", mountPoint + @"\Users\" + username + @"\AppData\Local");

                            else pathToFile = path[i].Replace("%windrive%", mountPoint);
                        }
                        else
                        {
                            if (path[i].Contains("%windir%")) pathToFile = path[i].Replace("%windir%", Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Windows"));

                            else if (path[i].Contains("%userprofile%")) pathToFile = path[i].Replace("%userprofile%", Path.Combine(Path.GetPathRoot(Environment.SystemDirectory), "Users", Environment.UserName));

                            else if (path[i].Contains("%appdata%")) pathToFile = path[i].Replace(@"%appdata%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));

                            else if (path[i].Contains("%localappdata%")) pathToFile = path[i].Replace(@"%localappdata%", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));

                            else pathToFile = path[i].Replace("%windrive%", Path.GetPathRoot(Environment.SystemDirectory));
                        }

                        File.Delete(pathToFile);
                    }

                    if (fixDetails.RequireRestart == true) requireRestart = true;
                }

                // Check if restart is required
                if (requireRestart == true && separateDriveCheckBox.IsChecked == false)
                {
                    ContentDialog dialog = new ContentDialog();
                    dialog.Title = "Information";
                    dialog.Content = "A fix that requires a restart has been successfully applied. You will need to restart to see the changes take effect. Restart now?";
                    dialog.PrimaryButtonText = "Yes";
                    dialog.SecondaryButtonText = "No";
                    dialog.DefaultButton = ContentDialogButton.Primary;
                    var result = await dialog.ShowAsync();
                    if (result == ContentDialogResult.Primary)
                    {
                        Process restartcomputer = new Process();
                        restartcomputer.StartInfo.FileName = "shutdown.exe";
                        restartcomputer.StartInfo.Arguments = "-r -t 0";
                        restartcomputer.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                        restartcomputer.Start();
                    }
                } else
                {
                    ContentDialog dialog = new ContentDialog();
                    dialog.Title = "Information";
                    dialog.Content = $@"The fix ""{name}"" has been applied successfully.";
                    dialog.PrimaryButtonText = "OK";
                    dialog.DefaultButton = ContentDialogButton.Primary;
                    await dialog.ShowAsync();
                }
            } catch (Exception ex)
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                if (ex.Message.Contains("No value exists with that name."))
                {
                    dialog.Content = $"There was an error applying the fix: {name}. \nThe fix was likely not needed in the first place.";
                }
                else
                {
                    dialog.Content = $"There was an error applying the fix: {name}. \n{ex.Message}";
                }
                dialog.PrimaryButtonText = "OK";
                dialog.DefaultButton = ContentDialogButton.Primary;
                await dialog.ShowAsync();
            }
        }

        private void launchAutomaticRepair_Click(object sender, RoutedEventArgs e)
        {
            if (separateDriveCheckBox.IsChecked == true)
            {
                AutomaticRepair automaticrepair = new AutomaticRepair(true);
                automaticrepair.ShowDialog();
            }
            else
            {
                AutomaticRepair automaticrepair = new AutomaticRepair(false);
                automaticrepair.ShowDialog();
            }
        }

        private void stripCriticalProcess_Click(object sender, EventArgs e)
        {
            StripCriticalProcessProperty stripCriticalProcessProperty = new StripCriticalProcessProperty();
            stripCriticalProcessProperty.ShowDialog();
        }

        private void reenableRegistry_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Re-enable Registry Editor");
        }

        private void reenableTaskManager_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Re-enable Task Manager");
        }

        private void reenableCommandPrompt_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Re-enable Command Prompt");
        }

        private void reenableUAC_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Re-enable User Account Control");
        }

        private void reenableWinDefender_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Windows Defender");
        }

        private void reenableThemeSettings_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Theme Settings");
        }

        private void reenableWallpaperSettings_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Wallpaper Settings");
        }

        private void reenableColourSettings_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Colour Settings");
        }

        private void reenableRun_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Run");
        }

        private void reenableWinKeys_Click(object sender, RoutedEventArgs e)
        {
            ApplyFix_Handler("Re-enable Windows key");
        }

        private void resetExeIcons_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Reset .exe icons");
        }

        private void resetTxtIcons_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Reset .txt icons");
        }

        private void resetShellKey_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Reset Shell key");
        }

        private void resetUserinitKey_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Reset Userinit key");
        }

        private void removeKeyboardRestrictions_Click(object sender, EventArgs e)
        {
            ApplyFix_Handler("Remove keyboard restrictions");
        }

        private void openRegistryEditor_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("regedit.exe");
        }

        private async void resetMouseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                RegistryKey resetmousebutton = hkcuPath.OpenSubKey(@"Control Panel\Mouse", true);
                string swapMouseButtonsValue = Convert.ToString(resetmousebutton.GetValue("SwapMouseButtons"));
                string newSwapMouseButtonsValue = swapMouseButtonsValue == "1" ? "0" : "1";

                resetmousebutton.SetValue("SwapMouseButtons", newSwapMouseButtonsValue);

                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Information";
                dialog.Content = $"The primary mouse button has been set to the {(newSwapMouseButtonsValue == "0" ? "left" : "right")} mouse button. However, you will need to restart in order to see the changes take effect. Restart now?";
                dialog.DefaultButton = ContentDialogButton.Primary;
                dialog.PrimaryButtonText = "Yes";
                dialog.SecondaryButtonText = "No";
                dialog.DefaultButton = ContentDialogButton.Primary;
                var result = await dialog.ShowAsync();
                if (result == ContentDialogResult.Primary)
                {
                    Process restartcomputer = new Process();
                    restartcomputer.StartInfo.FileName = "shutdown.exe";
                    restartcomputer.StartInfo.Arguments = "-r -t 0";
                    restartcomputer.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                    restartcomputer.Start();
                }
            }
            catch
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                dialog.Content = "There was an error toggling the primary mouse buttons. Do I have sufficient permissions?";
                dialog.PrimaryButtonText = "OK";
                dialog.DefaultButton = ContentDialogButton.Primary;
                await dialog.ShowAsync();
            }
        }

        private void openCommandPrompt_Click(object sender, RoutedEventArgs e)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Verb = "runas";
            process.Start();
        }

        private void openTaskManager_Click(object sender, RoutedEventArgs e)
        {
            Process.Start("taskmgr.exe");
        }

        private void exit_Click(object sender, RoutedEventArgs e)
        {
            Environment.Exit(0);
        }

        private void systemSettingMenuItem_Checked(object sender, RoutedEventArgs e)
        {
            RegistryKey lightdarkmode = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            ThemeManager.Current.ApplicationTheme = null;
            lightDarkButton.IsEnabled = false;
            try
            {
                lightdarkmode.DeleteValue("DarkMode");
            }
            catch { }

        }

        private void lightDarkButton_Click(object sender, RoutedEventArgs e)
        {
            RegistryKey lightdarkmode = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            if (ThemeManager.Current.ApplicationTheme == null || ThemeManager.Current.ApplicationTheme == ApplicationTheme.Light)
            {
                ThemeManager.Current.ApplicationTheme = ApplicationTheme.Dark;
                lightdarkmode.SetValue("DarkMode", 1);
            }
            else
            {
                ThemeManager.Current.ApplicationTheme = ApplicationTheme.Light;
                lightdarkmode.SetValue("DarkMode", 0);
            }
        }

        private void systemSettingMenuItem_Unchecked(object sender, RoutedEventArgs e)
        {
            RegistryKey lightdarkmode = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            ThemeManager.Current.ApplicationTheme = ApplicationTheme.Light;
            lightDarkButton.IsEnabled = true;
            lightdarkmode.SetValue("DarkMode", 0);
        }

        private void alwaysOnTop_Checked(object sender, RoutedEventArgs e)
        {
            alwaysOnTopMenuItem.IsChecked = true;
            this.Topmost = true;
            RegistryKey topmost = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            topmost.SetValue("TopMost", 1);
        }

        private void alwaysOnTop_Unchecked(object sender, RoutedEventArgs e)
        {
            this.Topmost = false;
            RegistryKey topmost = Registry.CurrentUser.CreateSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            topmost.SetValue("TopMost", 0);
        }

        private void runElevatedMenuItem_Click(object sender, RoutedEventArgs e)
        {
            RunElevated runelevated = new RunElevated();
            runelevated.ShowDialog();
        }

        private void runSystemMenuItem_Click(object sender, RoutedEventArgs e)
        {
            RunSystem runsystem = new RunSystem();
            runsystem.ShowDialog();
        }

        private void separateDriveText_Click(object sender, RoutedEventArgs e)
        {
            if (separateDriveCheckBox.IsChecked == true)
            {
                separateDriveCheckBox.IsChecked = false;
                SeparateDrive separateDrive = new SeparateDrive();
                separateDrive.RequirementMet += SeparateDrive_RequirementMet;
                separateDrive.ShowDialog();
            }
            else
            {
                stripCriticalProcess.IsEnabled = true;

                // Unload remote hives
                Process unloadSoftwareHive = new Process();
                unloadSoftwareHive.StartInfo.FileName = "reg.exe";
                unloadSoftwareHive.StartInfo.Arguments = @"unload ""HKLM\OfflineSoftware""";
                unloadSoftwareHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                unloadSoftwareHive.Start();

                Process unloadSystemHive = new Process();
                unloadSystemHive.StartInfo.FileName = "reg.exe";
                unloadSystemHive.StartInfo.Arguments = @"unload ""HKLM\OfflineSystem""";
                unloadSystemHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                unloadSystemHive.Start();

                Process unloadUserHive = new Process();
                unloadUserHive.StartInfo.FileName = "reg.exe";
                unloadUserHive.StartInfo.Arguments = @"unload ""HKLM\OfflineUser""";
                unloadUserHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                unloadUserHive.Start();

                // Set variables
                hklmSoftwarePath = Registry.LocalMachine.OpenSubKey("SOFTWARE", true);
                hklmSystemPath = Registry.LocalMachine.OpenSubKey("SYSTEM", true);
                hkcuPath = Registry.CurrentUser;
            }
        }

        private void SeparateDrive_RequirementMet(object sender, EventArgs e)
        {
            separateDriveCheckBox.IsChecked = true;
            stripCriticalProcess.IsEnabled = false;

            RegistryKey checkOperationsLocation = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            mountPoint = checkOperationsLocation.GetValue("MountPoint").ToString();
            username = checkOperationsLocation.GetValue("TargetUsername").ToString();

            // Load remote hives
            Process loadSoftwareHive = new Process();
            loadSoftwareHive.StartInfo.FileName = "reg.exe";
            loadSoftwareHive.StartInfo.Arguments = @"load ""HKLM\OfflineSoftware"" """ + mountPoint + @"\Windows\System32\config\SOFTWARE" + @"""";
            loadSoftwareHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadSoftwareHive.Start();

            Process loadSystemHive = new Process();
            loadSystemHive.StartInfo.FileName = "reg.exe";
            loadSystemHive.StartInfo.Arguments = @"load ""HKLM\OfflineSystem"" """ + mountPoint + @"\Windows\System32\config\SYSTEM" + @"""";
            loadSystemHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadSystemHive.Start();

            Process loadUserHive = new Process();
            loadUserHive.StartInfo.FileName = "reg.exe";
            loadUserHive.StartInfo.Arguments = @"load ""HKLM\OfflineUser"" """ + mountPoint + @"\Users\" + username + @"\NTUSER.dat" + @"""";
            loadUserHive.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadUserHive.Start();

            // Set variables
            hklmSoftwarePath = Registry.LocalMachine.OpenSubKey("OfflineSoftware", true);
            hklmSystemPath = Registry.LocalMachine.OpenSubKey("OfflineSystem", true);
            hkcuPath = Registry.LocalMachine.OpenSubKey("OfflineUser", true);
        }
    }
}
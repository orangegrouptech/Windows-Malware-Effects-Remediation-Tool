using iNKORE.UI.WPF.Modern.Controls;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Xml.Linq;
using static Windows_Malware_Effects_Remediation_Tool.RepairClasses;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for AutomaticRepair.xaml
    /// </summary>
    public partial class AutomaticRepair : Window
    {
        public AutomaticRepair(bool separateDrive)
        {
            InitializeComponent();
            if (Convert.ToInt32(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool").GetValue("TopMost")) == 1)
                this.Topmost = true;

            DiagnoseIssues(repairClassesGlobal);
            separateDriveFix = separateDrive;
        }

        public static bool separateDriveFix = false;

        public static string mountPoint;

        public static string username;

        private RepairClasses repairClassesGlobal = new RepairClasses();

        public void DiagnoseIssues(RepairClasses repairClasses)
        {
            // Load Registry hives from target drive if separateDrive is true
            if (separateDriveFix == true)
            {
                LoadSeparateHive();
            }

            // Initialise HKLM and HKCU paths
            RegistryKey hklmSoftwarePath;
            RegistryKey hklmSystemPath;
            RegistryKey hkcuPath;

            if (separateDriveFix == true)
            {
                hklmSoftwarePath = Registry.LocalMachine.OpenSubKey(@"OfflineSoftware", true);
                hklmSystemPath = Registry.LocalMachine.OpenSubKey(@"OfflineSystem", true);
                hkcuPath = Registry.LocalMachine.OpenSubKey(@"OfflineUser", true);
            }
            else
            {
                hklmSoftwarePath = Registry.LocalMachine.OpenSubKey(@"SOFTWARE", true);
                hklmSystemPath = Registry.LocalMachine.OpenSubKey(@"SYSTEM", true);
                hkcuPath = Registry.CurrentUser;
            }

            // Iterate through the list of possible fixes and check if a fix is needed
            int x = 0;
            foreach (var fix in repairClasses.fixInformation)
            {
                try
                {
                    x++;
                    searchProgress.Content = $"Searching for available fixes ({x} of {repairClasses.fixInformation.Count})";

                    var name = fix.Name;
                    var fixType = fix.Type;
                    var path = fix.Path;
                    var key = fix.Key;
                    var value = fix.Value;
                    var nullable = fix.Nullable;

                    for (int i = 0; i < fixType.Count; i++)
                    {
                        if (fix.IsSelected == false)
                        {
                            if (fixType[i] == FixType.Registry)
                            {
                                // Determine Registry hive
                                RegistryKey registryKey;
                                if (path[i].Contains(@"HKEY_LOCAL_MACHINE\SOFTWARE"))
                                {
                                    registryKey = hklmSoftwarePath.CreateSubKey(path[i].Replace(@"HKEY_LOCAL_MACHINE\SOFTWARE\", ""), true);
                                }
                                else if (path[i].Contains(@"HKEY_LOCAL_MACHINE\SYSTEM"))
                                {
                                    registryKey = hklmSystemPath.CreateSubKey(path[i].Replace(@"HKEY_LOCAL_MACHINE\SYSTEM\", ""), true);
                                }
                                else if (path[i].Contains("HKEY_CURRENT_USER"))
                                {
                                    registryKey = hkcuPath.CreateSubKey(path[i].Replace(@"HKEY_CURRENT_USER\", ""), true);
                                }
                                else
                                {
                                    throw new Exception($@"The fix ""{name}"" was not configured correctly in RepairClasses: Invalid hive in Path (Registry)");
                                }

                                if (registryKey.GetValue(key[i]) != null)
                                {
                                    // Check if value is an integer, convert to integer if so
                                    int valueInt;
                                    if (int.TryParse(value[i], out valueInt))
                                    {
                                        // If Registry key exists and value is incorrect, add to the checklistbox
                                        if (!(registryKey.GetValue(key[i]) is int) || Convert.ToInt32(registryKey.GetValue(key[i])) != valueInt)
                                        {
                                            // Define binding
                                            Binding binding = new Binding("RepairClasses.FixTask.IsSelected");
                                            binding.NotifyOnSourceUpdated = true;
                                            binding.UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged;

                                            // Add to checklistbox
                                            fix.IsSelected = true;
                                            fixList.Items.Add(fix);
                                        }
                                        registryKey.Dispose();
                                    } else
                                    {
                                        // If Registry key exists and value is incorrect, add to the checklistbox
                                        if (!(registryKey.GetValue(key[i]) is string) || registryKey.GetValue(key[i]).ToString() != value[i])
                                        {
                                            // Define binding
                                            Binding binding = new Binding("RepairClasses.FixTask.IsSelected");
                                            binding.NotifyOnSourceUpdated = true;
                                            binding.UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged;

                                            // Add to checklistbox
                                            fix.IsSelected = true;
                                            fixList.Items.Add(fix);
                                        }
                                        registryKey.Dispose();
                                    }
                                }
                            }
                            else
                            {
                                // Add to checklistbox
                                CheckBox checkBox = new CheckBox();
                                checkBox.Content = name;
                                checkBox.IsChecked = true;
                                fixList.Items.Add(checkBox);
                                fix.IsSelected = true;
                            }
                        }
                    }
                } catch (Exception ex)
                {
                    ContentDialog dialog = new ContentDialog();
                    dialog.Title = "Error";
                    dialog.Content = $"There was an error diagnosing the issue: {fix.Name}. \n{ex.Message}";
                    dialog.PrimaryButtonText = "OK";
                    dialog.DefaultButton = ContentDialogButton.Primary;
                    dialog.ShowAsync();
                    this.Close();
                }
            }

            // Show the checklistbox
            searchingForProblems.Visibility = Visibility.Collapsed;
            searchingForProblemsProgressBar.Visibility = Visibility.Collapsed;
            searchComplete.Visibility = Visibility.Visible;
            searchCompleteDescription.Visibility = Visibility.Visible;
            applyFix.Visibility = Visibility.Visible;
            fixList.Visibility = Visibility.Visible;
            if (fixList.Items.Count == 0)
            {
                goodToGo.Visibility = Visibility.Visible;
                applyFix.IsEnabled = false;
            }

            // Unload Registry hives if separateDrive is true
            if (separateDriveFix == true)
            {
                UnloadSeparateHive();
            }

            repairClassesGlobal = repairClasses;
        }

        private async void applyFix_Click(object sender, RoutedEventArgs e)
        {
            // Hide the checklistbox and show the progress bar
            searchComplete.Visibility = Visibility.Collapsed;
            searchCompleteDescription.Visibility = Visibility.Collapsed;
            searchProgress.Visibility = Visibility.Collapsed;
            applyFix.Visibility = Visibility.Collapsed;
            fixList.Visibility = Visibility.Collapsed;
            attemptingRepairs.Visibility = Visibility.Visible;
            attemptingRepairsProgressBar.Visibility = Visibility.Visible;
            repairProgress.Visibility = Visibility.Visible;

            // Load Registry hives from target drive if separateDrive is true
            if (separateDriveFix == true)
            {
                LoadSeparateHive();
            }

            // Initialise HKLM and HKCU paths
            RegistryKey hklmSoftwarePath;
            RegistryKey hklmSystemPath;
            RegistryKey hkcuPath;

            if (separateDriveFix == true)
            {
                hklmSoftwarePath = Registry.LocalMachine.OpenSubKey(@"OfflineSoftware", true);
                hklmSystemPath = Registry.LocalMachine.OpenSubKey(@"OfflineSystem", true);
                hkcuPath = Registry.LocalMachine.OpenSubKey(@"OfflineUser", true);
            }
            else
            {
                hklmSoftwarePath = Registry.LocalMachine.OpenSubKey(@"SOFTWARE", true);
                hklmSystemPath = Registry.LocalMachine.OpenSubKey(@"SYSTEM", true);
                hkcuPath = Registry.CurrentUser;
            }

            bool requireRestart = false;

            foreach (var fix in repairClassesGlobal.fixInformation)
            {
                try
                {
                    var name = fix.Name;
                    var fixType = fix.Type;
                    var path = fix.Path;
                    var key = fix.Key;
                    var value = fix.Value;
                    var nullable = fix.Nullable;

                    for (int i = 0; i < fixType.Count; i++)
                    {
                        if (fix.IsSelected == true)
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
                                if (separateDriveFix == true)
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

                            if (fix.RequireRestart == true) requireRestart = true;
                        }
                        repairProgress.Content = $"Fixed {i + 1} of {fixType.Count} issues";
                    }
                }
                catch (Exception ex)
                {
                    ContentDialog dialog = new ContentDialog();
                    dialog.Title = "Error";
                    dialog.Content = $"There was an error applying the fix: {fix.Name}. \n{ex.Message}";
                    dialog.PrimaryButtonText = "OK";
                    dialog.DefaultButton = ContentDialogButton.Primary;
                    await dialog.ShowAsync();
                    this.Close();
                }
            }

            if (separateDriveFix == true)
            {
                UnloadSeparateHive();
            }

            // Show the success message
            await Delay(500);
            attemptingRepairs.Visibility = Visibility.Collapsed;
            attemptingRepairsProgressBar.Visibility = Visibility.Collapsed;
            repairProgress.Visibility = Visibility.Collapsed;

            FinishedPage finishedPage = new FinishedPage();
            finishedPage.finishedText.Content = "Fixes applied successfully";
            finishedPage.progressText.Content = "All requested fixes have been applied successfully!";
            this.Content = finishedPage;

            // Check if restart is required
            if (requireRestart == true && separateDriveFix == false)
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
            }
        }

        private async void LoadSeparateHive()
        {
            RegistryKey checkOperationsLocation = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
            mountPoint = checkOperationsLocation.GetValue("MountPoint").ToString();
            username = checkOperationsLocation.GetValue("TargetUsername").ToString();

            Process loadHiveUser = new Process();
            loadHiveUser.StartInfo.FileName = "reg.exe";
            loadHiveUser.StartInfo.Arguments = @"load ""HKLM\OfflineUser"" """ + mountPoint + @"\Users\" + username + @"\NTUSER.dat" + @"""";
            loadHiveUser.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadHiveUser.Start();

            Process loadHiveSoftware = new Process();
            loadHiveSoftware.StartInfo.FileName = "reg.exe";
            loadHiveSoftware.StartInfo.Arguments = @"load ""HKLM\OfflineSoftware"" """ + mountPoint + @"\Windows\System32\config\SOFTWARE" + @"""";
            loadHiveSoftware.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadHiveSoftware.Start();

            Process loadHiveSystem = new Process();
            loadHiveSystem.StartInfo.FileName = "reg.exe";
            loadHiveSystem.StartInfo.Arguments = @"load ""HKLM\OfflineSystem"" """ + mountPoint + @"\Windows\System32\config\SYSTEM" + @"""";
            loadHiveSystem.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            loadHiveSystem.Start();
            await Delay(500);
        }

        private void UnloadSeparateHive()
        {
            Process unloadHiveUser = new Process();
            unloadHiveUser.StartInfo.FileName = "reg.exe";
            unloadHiveUser.StartInfo.Arguments = @"unload ""HKLM\OfflineUser""";
            unloadHiveUser.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            unloadHiveUser.Start();

            Process unloadHiveSoftware = new Process();
            unloadHiveSoftware.StartInfo.FileName = "reg.exe";
            unloadHiveSoftware.StartInfo.Arguments = @"unload ""HKLM\OfflineSoftware""";
            unloadHiveSoftware.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            unloadHiveSoftware.Start();

            Process unloadHiveSystem = new Process();
            unloadHiveSystem.StartInfo.FileName = "reg.exe";
            unloadHiveSystem.StartInfo.Arguments = @"unload ""HKLM\OfflineSystem""";
            unloadHiveSystem.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            unloadHiveSystem.Start();
        }

        private async Task Delay(int howlong)
        {
            await Task.Delay(howlong);
        }

        private void repairSuccessfulCloseButton_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void refreshButton_Click(object sender, RoutedEventArgs e)
        {
            RepairClasses repairClasses = new RepairClasses();
            DiagnoseIssues(repairClasses);
        }
    }
}
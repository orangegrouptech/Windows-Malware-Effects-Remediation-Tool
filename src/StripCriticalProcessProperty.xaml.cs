using iNKORE.UI.WPF.Modern.Controls;
using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using static Windows_Malware_Effects_Remediation_Tool.ProcessInformation;
using static Windows_Malware_Effects_Remediation_Tool.WindowsAPIMethods;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for StripCriticalProcessProperty.xaml
    /// </summary>

    public partial class StripCriticalProcessProperty : Window
    {
        private LoadingPage loadingPage = new LoadingPage();
        private ProcessInformation processInformationGlobal = new ProcessInformation();

        public StripCriticalProcessProperty()
        {
            InitializeComponent();
            if (Convert.ToInt32(Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool").GetValue("TopMost")) == 1)
                this.Topmost = true;

            searchComplete.Visibility = Visibility.Collapsed;
            searchCompleteDescription.Visibility = Visibility.Collapsed;
            killList.Visibility = Visibility.Collapsed;
            refreshButton.Visibility = Visibility.Collapsed;
            criticalProcessSubmit.Visibility = Visibility.Collapsed;

            Task.Run(() => StartChecks(loadingPage, processInformationGlobal));
        }

        private void StartChecks(LoadingPage loadingPage, ProcessInformation processInformation)
        {

            try
            {
                Application.Current.Dispatcher.Invoke(() =>
                {
                    searchComplete.Visibility = Visibility.Collapsed;
                    searchCompleteDescription.Visibility = Visibility.Collapsed;
                    killList.Visibility = Visibility.Collapsed;
                    refreshButton.Visibility = Visibility.Collapsed;
                    criticalProcessSubmit.Visibility = Visibility.Collapsed;

                    frame.Visibility = Visibility.Visible;
                    frame.Content = loadingPage;
                    killList.Items.Clear();
                });

                // Exclusions
                string[] extensionlessProcesses =
                {
                    "System",
                    "System Idle Process",
                    "Secure System",
                    "Registry"
                };

                string[] systemUsers =
                {
                    "SYSTEM",
                    "LOCAL SERVICE",
                    "NETWORK SERVICE",
                    "UMFD",
                    "DWM"
                };

                string[] excludedPaths =
                {
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\csrss.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\wininit.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\winlogon.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\dashost.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\wbem\wmiprvse.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\dwm.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\fontdrvhost.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\system32\wlanext.exe".ToLower(),
                    $@"{Environment.GetFolderPath(Environment.SpecialFolder.Windows)}\explorer.exe".ToLower()
                };

                // Process Check
                ManagementObjectSearcher Processes = new ManagementObjectSearcher("SELECT * FROM Win32_Process");
                int i = 0;
                int numberOfProcesses = Processes.Get().Count;
                Process.EnterDebugMode();
                //foreach (ManagementObject process in Processes.Get())
                Parallel.ForEach(Processes.Get().Cast<ManagementObject>(), process =>
                {
                    Interlocked.Increment(ref i);
                    Application.Current.Dispatcher.Invoke(() => loadingPage.progressText.Content = $"Processed {i} of {numberOfProcesses} processes");

                    // Initialise process variables
                    string processName = process["Name"].ToString();
                    int processID = Convert.ToInt32(process["ProcessId"]);
                    string processPath = process["ExecutablePath"]?.ToString() ?? "";

                    // Highly protected kernel mode processes will NOT return a path, assume they're clean (not that we can terminate them in user mode anyway)
                    if (processPath == "") return;

                    // Get process owner
                    string owner = "";
                    try
                    {
                        string[] OwnerInfo = new string[2];
                        process.InvokeMethod("GetOwner", OwnerInfo);
                        owner = OwnerInfo[0];
                    }
                    catch
                    {
                        owner = "Unknown";
                    }

                    // Skip "System", "System Idle Process" and other extensionless processes
                    if (extensionlessProcesses.Contains(processName)) return;

                    // Skip current process
                    if (processID == Process.GetCurrentProcess().Id) return;

                    // Skip whitelisted processes
                    if (excludedPaths.Contains(processPath.ToLower())) return;

                    // If the process is not signed by Microsoft or executing user is not SYSTEM, LOCAL SERVICE or NETWORK SERVICE AND not signed by Microsoft, add it to the list
                    bool register = false;
                    if (systemUsers.Contains(owner))
                    {
                        try
                        {
                            X509Certificate2 signerCert = new X509Certificate2(X509Certificate.CreateFromSignedFile(processPath));
                            if (!signerCert.SubjectName.Name.Contains("Microsoft"))
                            {
                                register = true;
                            }
                        }
                        catch
                        {
                            register = true;
                        }
                    }
                    else
                    {
                        register = true;
                    }

                    // Register registered apps to the list
                    if (register == true)
                    {
                        // Check if process is critical
                        uint isCritical = 2;
                        GCHandle gch = GCHandle.Alloc(isCritical, GCHandleType.Pinned);
                        try
                        {
                            NtQueryInformationProcess(Process.GetProcessById(processID).Handle, PROCESS_INFORMATION_CLASS.ProcessBreakOnTermination, gch.AddrOfPinnedObject(), (uint)Marshal.SizeOf(typeof(uint)), out uint returnLength);
                            isCritical = (uint)Marshal.ReadInt32(gch.AddrOfPinnedObject());
                        }
                        catch
                        {
                            return;
                        }

                        // Add process info into the dictionary
                        if (isCritical == 1)
                        {
                            ProcessInfo processInfo = new ProcessInfo(processName, processID, owner);
                            processInformation.ProcessList.Add(processID, processInfo);

                            // Add the object to the list
                            Application.Current.Dispatcher.Invoke(() =>
                            {
                                killList.Items.Add(processInfo);
                            });
                        }
                    }
                });

                // Handle some UI stuff
                Application.Current.Dispatcher.Invoke(() =>
                {
                    // Show the DataGrid and related UI elements
                    searchComplete.Visibility = Visibility.Visible;
                    searchCompleteDescription.Visibility = Visibility.Visible;
                    killList.Visibility = Visibility.Visible;
                    refreshButton.Visibility = Visibility.Visible;
                    criticalProcessSubmit.Visibility = Visibility.Visible;

                    frame.Visibility = Visibility.Collapsed;
                    killList.Items.SortDescriptions.Add(new System.ComponentModel.SortDescription("Name", System.ComponentModel.ListSortDirection.Ascending)); // Sort by alphabetical order

                    // Disable submit button if there are no processes to terminate
                    if (!processInformation.ProcessList.Values.Any(x => x.isSelected == true))
                    {
                        criticalProcessSubmit.IsEnabled = false;
                        selectAll.IsEnabled = false;
                    }
                    else
                    {
                        criticalProcessSubmit.IsEnabled = true;
                        selectAll.IsEnabled = true;
                    }
                });

                processInformationGlobal = processInformation;
                Process.LeaveDebugMode();
            }
            catch (Exception ex)
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                dialog.Content = $"There was an error while checking for critical processes. \n{ex.Message}";
                dialog.PrimaryButtonText = "OK";
                dialog.DefaultButton = ContentDialogButton.Primary;
                dialog.ShowAsync();
                this.Close();
            }
        }

        private async void criticalProcessSubmit_Click(object sender, EventArgs e)
        {
            LoadingPage loadingPage = new LoadingPage();
            frame.Content = loadingPage;
            frame.Visibility = Visibility.Visible;

            searchComplete.Visibility = Visibility.Collapsed;
            searchCompleteDescription.Visibility = Visibility.Collapsed;
            killList.Visibility = Visibility.Collapsed;
            refreshButton.Visibility = Visibility.Collapsed;
            criticalProcessSubmit.Visibility = Visibility.Collapsed;

            // Iterate through the list and terminate the selected processes
            await Task.Run(async () =>
            {
                int i = 1;
                try
                {
                    var listToTerminate = processInformationGlobal.ProcessList.Values.Where(x => x.isSelected == true);
                    foreach (var item in listToTerminate)
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            loadingPage.progressText.Content = $"Terminating {i} of {listToTerminate.Count()} processes";
                            loadingPage.searchingText.Content = "Terminating processes";
                        });
                        await Task.Delay(500);
                        int isCritical = 0;
                        Process.EnterDebugMode();
                        NtSetInformationProcess(Process.GetProcessById(item.ID).Handle, PROCESS_INFORMATION_CLASS.ProcessBreakOnTermination, ref isCritical, sizeof(int));
                        Process.GetProcessById(item.ID).Kill();
                        i++;
                        await Task.Delay(500);
                    }

                    Process.LeaveDebugMode();
                }
                catch (Exception ex)
                {
                    ContentDialog dialog = new ContentDialog();
                    dialog.Title = "Error";
                    dialog.Content = $@"There was an error while terminating the process ""{processInformationGlobal.ProcessList[i - 1]}"". \n{ex.Message}";
                    dialog.PrimaryButtonText = "OK";
                    dialog.DefaultButton = ContentDialogButton.Primary;
                    await dialog.ShowAsync();
                    this.Close();
                }
            });
            FinishedPage finishedPage = new FinishedPage();
            frame.Content = finishedPage;
        }

        private void refreshButton_Click(object sender, RoutedEventArgs e)
        {
            LoadingPage loadingPage = new LoadingPage();
            ProcessInformation processInformation = new ProcessInformation();
            Task.Run(() => StartChecks(loadingPage, processInformation));
        }

        private bool thatsMe = false;

        // Checkbox logic
        private void CheckBox_Checked(object sender, RoutedEventArgs e)
        {
            if (thatsMe == false)
            {
                if (processInformationGlobal.ProcessList.Values.All(x => x.isSelected == true))
                {
                    thatsMe = true;
                    selectAll.IsChecked = true;
                    criticalProcessSubmit.IsEnabled = true;
                    thatsMe = false;
                }
                else if (processInformationGlobal.ProcessList.Values.Any(x => x.isSelected == true))
                {
                    thatsMe = true;
                    selectAll.IsChecked = null;
                    criticalProcessSubmit.IsEnabled = true;
                    thatsMe = false;
                }
            }
            else
            {
                thatsMe = false;
            }
        }

        private void CheckBox_Unchecked(object sender, RoutedEventArgs e)
        {
            if (thatsMe == false)
            {
                if (processInformationGlobal.ProcessList.Values.All(x => x.isSelected == false))
                {
                    thatsMe = true;
                    selectAll.IsChecked = false;
                    criticalProcessSubmit.IsEnabled = false;
                    thatsMe = false;
                }
                else if (processInformationGlobal.ProcessList.Values.Any(x => x.isSelected == true))
                {
                    thatsMe = true;
                    selectAll.IsChecked = null;
                    criticalProcessSubmit.IsEnabled = true;
                    thatsMe = false;
                }
            }
            else
            {
                thatsMe = false;
            }
        }

        // Select all checkboxes logic
        private void selectAll_Checked(object sender, RoutedEventArgs e)
        {
            if (thatsMe == false)
            {
                foreach (ProcessInfo process in processInformationGlobal.ProcessList.Values)
                {
                    thatsMe = true;
                    process.isSelected = true;
                }
                criticalProcessSubmit.IsEnabled = true;
                thatsMe = false;
            }
            else
            {
                thatsMe = false;
            }
        }

        private void selectAll_Unchecked(object sender, RoutedEventArgs e)
        {
            if (thatsMe == false)
            {
                foreach (ProcessInfo process in processInformationGlobal.ProcessList.Values)
                {
                    thatsMe = true;
                    process.isSelected = false;
                }
                criticalProcessSubmit.IsEnabled = false;
                thatsMe = false;
            }
            else
            {
                thatsMe = false;
            }
        }

        private void selectAll_Indeterminate(object sender, RoutedEventArgs e)
        {
            if (thatsMe == false)
            {
                selectAll.IsChecked = false;
            }
            else
            {
                thatsMe = false;
            }
        }
    }
}
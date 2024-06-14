using System;
using System.Windows;
using System.IO;
using iNKORE.UI.WPF.Modern.Controls;
using Microsoft.Win32;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for SeparateDrive.xaml
    /// </summary>
    public partial class SeparateDrive : Window
    {
        public event EventHandler RequirementMet;
        public SeparateDrive()
        {
            InitializeComponent();
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

        private async void separateDriveSubmit_Click(object sender, RoutedEventArgs e)
        {
            string driveLetter = "";
            if (!driveLetterTextBox.Text.Contains(":"))
            {
                driveLetter = driveLetterTextBox.Text + ":";
            } else
            {
                driveLetter = driveLetterTextBox.Text;
            }
            if (!Directory.Exists(driveLetter))
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                dialog.Content = "The mount point is invalid.";
                dialog.DefaultButton = ContentDialogButton.Primary;
                dialog.PrimaryButtonText = "OK";
                await dialog.ShowAsync();
            } else if (usernameTextBox.Text == "")
            {
                ContentDialog dialog = new ContentDialog();
                dialog.Title = "Error";
                dialog.Content = "The username field cannot be empty.";
                dialog.DefaultButton = ContentDialogButton.Primary;
                dialog.PrimaryButtonText = "OK";
                await dialog.ShowAsync();
            } 
            else
            {
                RegistryKey registryKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Orange Group\Windows Malware Effects Remediation Tool", true);
                registryKey.SetValue("MountPoint", driveLetter);
                registryKey.SetValue("TargetUsername", usernameTextBox.Text);
                registryKey.Dispose();
                RequirementMet?.Invoke(this, EventArgs.Empty);
                this.Close();
            }
        }
    }
}

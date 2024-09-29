using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Diagnostics;
using Microsoft.Win32;
using System.IO;
using iNKORE.UI.WPF.Modern.Controls;

namespace Windows_Malware_Effects_Remediation_Tool
{
    /// <summary>
    /// Interaction logic for RunElevated.xaml
    /// </summary>
    public partial class RunElevated : Window
    {
        public RunElevated()
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

        private async void okButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                //Process.Start(runTextBox.Text); //Whoever thought this was a good idea is an idiot. Wait...
                ProcessStartInfo startProcess = new ProcessStartInfo()
                {
                    FileName = $@"{Environment.GetFolderPath(Environment.SpecialFolder.System)}\cmd.exe",
                    Arguments = $@"/c ""{runTextBox.Text}""",
                };
                Process.Start(startProcess); // I know I just called myself an idiot but I'm not sure of a better way to have it accept arguments and at the same time avoid showing that ugly command prompt window.

                runTextBox.IsEnabled = false;
                okButton.IsEnabled = false;
                cancelButton.IsEnabled = false;
                await Task.Delay(500);
                this.Close();
            } catch
            {
                ContentDialog contentDialog = new ContentDialog();
                contentDialog.Title = "Error";
                contentDialog.Content = "There was an error starting the process \"" + runTextBox.Text + "\". Make sure you typed the name correctly and try again.";
                contentDialog.PrimaryButtonText = "OK";
                contentDialog.DefaultButton = ContentDialogButton.Primary;
                await contentDialog.ShowAsync();

                runTextBox.IsEnabled = true;
                okButton.IsEnabled = true;
                cancelButton.IsEnabled = true;
            }
        }

        private async Task Delay(int howlong)
        {
            await Task.Delay(howlong);
        }

        private void Window_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if(e.Key == System.Windows.Input.Key.Return)
            {
                if(okButton.IsEnabled == true)
                {
                    okButton_Click(sender, e);
                } else {}
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

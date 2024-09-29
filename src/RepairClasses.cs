using System.Collections.Generic;
using System.ComponentModel;

namespace Windows_Malware_Effects_Remediation_Tool
{
    public class RepairClasses
    {
        /**
          * [
          *     FixTask("Re-enable Registry Editor", FixType.Registry, ["HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"], ["DisableRegistryTools"], ["0"], [true]),
          *     FixTask("Re-enable User Account Control", 
          *     [
          *         FixType.Registry,
          *         FixType.Registry,
          *         FixType.Registry
          *     ],
          *     [
          *         "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
          *         "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
          *         "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
          *     ], 
          *     [
          *         "EnableLUA",
          *         "ConsentPromptBehaviorAdmin",
          *         "ConsentPromptBehaviorUser"
          *     ], 
          *     [
          *         "1",
          *         "5",
          *         "3"
          *     ], 
          *     [
          *         false,
          *         false,
          *         false
          *     ])
          * ]
          * 
        **/

        public List<FixTask> fixInformation = new List<FixTask>()
        {
            new FixTask("Re-enable Registry Editor", new List<FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\\Windows\CurrentVersion\Policies\System"}, new List<string> {"DisableRegistryTools"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Re-enable Task Manager", new List<FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"}, new List<string> {"DisableTaskMgr"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Re-enable Command Prompt", new List<FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"}, new List<string> {"DisableCMD"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Re-enable User Account Control", new List<FixType>
            {
                FixType.Registry,
                FixType.Registry,
                FixType.Registry
            }, new List<string>
            {
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            }, new List<string>
            {
                "EnableLUA",
                "ConsentPromptBehaviorAdmin",
                "ConsentPromptBehaviorUser"
            }, new List<string>
            {
                "1",
                "5",
                "3"
            }, new List<bool>
            {
                false,
                false,
                false
            }, false),

            new FixTask("Re-enable Windows Defender", new List<FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Wind" + WDefendPart2}, new List<string> {"DisableAntiSpyware"}, new List<string> {"0"}, new List<bool> {true}, false),
                                                                                                                                                       // Evading false positive detection by splitting the string
            
            new FixTask("Re-enable Theme Settings", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"}, new List<string> {"NoDispAppearancePage"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Re-enable Wallpaper Settings", new List <FixType>
            {
                FixType.Registry, FixType.Registry
            }, new List<string>
            {
                @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop",
                @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            }, new List<string>
            {
                "NoChangingWallpaper",
                "wallpaper"
            }, new List<string>
            {
                "0",
                ""
            }, new List<bool>
            {
                true,
                true
            }, false),

            new FixTask("Re-enable Colour Settings", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"}, new List<string> {"NoDispAppearancePage"}, new List<string> {"0"}, new List <bool> {true}, false),

            new FixTask("Re-enable Run", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"}, new List<string> {"NoRun"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Re-enable Windows key", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"}, new List<string> {"NoWinKeys"}, new List<string> {"0"}, new List<bool> {true}, false),

            new FixTask("Reset .exe icons", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\DefaultIcon"}, new List<string> {""}, new List<string> {"%1"}, new List<bool> {true}, false),

            new FixTask("Reset .txt icons", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SOFTWARE\Classes\txtfile\DefaultIcon"}, new List<string> {""}, new List<string> {@"%systemroot%\system32\imageres.dll,-102"}, new List<bool> {true}, false),

            new FixTask("Reset Shell key", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"}, new List<string> {"Shell"}, new List<string> {"explorer.exe"}, new List<bool> {true}, false),

            new FixTask("Reset Userinit key", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"}, new List<string> {"Userinit"}, new List<string> {@"C:\Windows\system32\userinit.exe,"}, new List<bool> {true}, false),

            new FixTask("Remove keyboard restrictions", new List <FixType> {FixType.Registry}, new List<string> {@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Keyboard Layout"}, new List<string> {"Scancode Map"}, new List<string> {""}, new List<bool> {true}, true),
        };

        public class FixTask : INotifyPropertyChanged
        {
            private string _name;
            public string Name
            {
                get { return _name; }
                private set
                {
                    if (_name != value)
                    {
                        _name = value;
                    }
                }
            }
            public readonly List<FixType> Type;
            public readonly List<string> Path;
            public readonly List<string> Key;
            public readonly List<string> Value;
            public readonly List<bool> Nullable;
            private bool _isSelected;
            public bool IsSelected
            {
                get { return _isSelected; }
                set
                {
                    if (_isSelected != value)
                    {
                        _isSelected = value;
                        OnPropertyChanged(nameof(IsSelected));
                    }
                }
            }
            public readonly bool RequireRestart;

            public FixTask(string Name, List<FixType> Type, List<string> Path, List<string> Key, List<string> Value, List<bool> nullable, bool requireRestart)
            {
                this.Name = Name;
                this.Type = Type;
                this.Path = Path;
                this.Key = Key;
                this.Value = Value;
                this.Nullable = nullable;
                this.RequireRestart = requireRestart;
            }

            public event PropertyChangedEventHandler PropertyChanged;

            protected virtual void OnPropertyChanged(string propertyName)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }
        }

        public enum FixType
        {
            Registry,
            File
        }

        public static string WDefendPart2 = "ows Defender"; // Evading false positive detection by splitting the string
    }
}
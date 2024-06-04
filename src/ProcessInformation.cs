using System.Collections.Generic;
using System.ComponentModel;

namespace Windows_Malware_Effects_Remediation_Tool
{
    class ProcessInformation
    {
        /**
         * {
         *      1234: ProcessInfo("csrss.exe", 1234, "SYSTEM")
         *      5678: ProcessInfo("msedge.exe", 5678, "Administrator")
         * }
        **/

        public Dictionary<int, ProcessInfo> ProcessList = new Dictionary<int, ProcessInfo>();

        public class ProcessInfo : INotifyPropertyChanged
        {
            public string Name { get; }
            public int ID { get; }
            public string Username { get; }

            private bool _isSelected;
            public bool isSelected
            {
                get { return _isSelected; }
                set
                {
                    if (_isSelected != value)
                    {
                        _isSelected = value;
                        OnPropertyChanged(nameof(isSelected));
                    }
                }
            }

            public ProcessInfo(string name, int id, string username)
            {
                Name = name;
                ID = id;
                Username = username;
                isSelected = true;
            }

            public event PropertyChangedEventHandler PropertyChanged;

            protected virtual void OnPropertyChanged(string propertyName)
            {
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
            }
        }
    }
}
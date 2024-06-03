import wmi
import winreg
import win32com.client
#import win32api
import requests
import json
import psutil

program_names = []
path_to_file = []

def get_file_version(file_path):
    try:
        info = win32api.GetFileVersionInfo(file_path, '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        version = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
        return version
    except Exception as e:
        return str(e)
    

def get_windows_defender_last_scan_time():
    # Create a WMI object
    c = wmi.WMI(namespace='root\\Microsoft\\SecurityClient')

    # Query the Windows Defender Status
    try:
        for item in c.AntivirusProduct():
            print(f"Antivirus Name: {item.displayName}")
            print(f"Product State: {item.productState}")
            print(f"Last Scan: {item.lastQuickScanTime}")
    except Exception as e:
        print(f"An error occurred: {e}")


def get_nvd_results(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors

        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print(f"Error occurred: {e}")
        return None


def get_startup_programs():
        registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]

        startup_programs = []

        for hive, path in registry_paths:
            path_to_file.append(path)
            try:
                with winreg.OpenKey(hive, path) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            startup_programs.append((name, value))
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                # If the registry path does not exist, continue to the next one
                continue
        return startup_programs

def get_nvd_vulnerabilities(cpe):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {
        "cpeMatchString": cpe,
        "resultsPerPage": 20
    }
    response = requests.get(base_url, params=params)
    print(response)
    if(response.json):
        print("we have json")
        print(response.json)
    else:
        print("no json")
    return response.json()
    

def list_services():
    # Initialize the WMI
    c = wmi.WMI()

    # Get the list of all services
    for service in c.Win32_Service():
        print(f"Service Name: {service.Name}")
        print(f"Display Name: {service.DisplayName}")
        print(f"State: {service.State}")
        print(f"Start Mode: {service.StartMode}")
        print(f"Description: {service.Description}\n")


def list_scheduled_tasks():
    # Create a TaskScheduler object
    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()

    # Get the root folder
    root_folder = scheduler.GetFolder('\\')

    def list_tasks(folder):
        tasks = []
        for task in folder.GetTasks(0):
            program_names.append(task.Name)
            path_to_file.append(task.Path)
            task_info = {
                'Name': task.Name,
                'Path': task.Path,
                'Enabled': task.Enabled,
                'Last Run Time': task.LastRunTime if task.LastRunTime else 'Never',
                'Next Run Time': task.NextRunTime if task.NextRunTime else 'Not scheduled',
                'Status': task.State
            }
            tasks.append(task_info)

        # Recursively list tasks in subfolders
        for subfolder in folder.GetFolders(0):
            tasks.extend(list_tasks(subfolder))
        
        return tasks

    # Get all tasks starting from the root folder
    tasks = list_tasks(root_folder)
    
    return tasks


def get_installed_programs():
    programs = []

    # Registry keys to check for installed programs
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    ]

    for hive, path in registry_paths:
        path_to_file.append(path)
        try:
            with winreg.OpenKey(hive, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            programs.append(name)
                    except FileNotFoundError:
                        # DisplayName not found
                        pass
                    except OSError:
                        # Could not open subkey or other error
                        pass
        except OSError:
            # Could not open registry key or other error
            pass

    return programs


if __name__ == "__main__":
    #get_windows_defender_last_scan_time()
    programs = get_startup_programs()
    if programs:
        print("Startup Programs:")
        for name, value in programs:
            print(f"{name}: {value}")
    else:
        print("No startup programs found.")

    tasks = list_scheduled_tasks()
    if tasks:
        print("Scheduled Tasks:")
        for task in tasks:
            '''print(f"Name: {task['Name']}")
            print(f"Path: {task['Path']}")
            print(f"Enabled: {task['Enabled']}")
            print(task['Next Run Time'])'''
            #print(f"Last Run Time: {last_run}")
            #print(f"Next Run Time: {next_run}")
            #print(f"Status: {task['Status']}")
            #print("-" * 40)
    else:
        print("No scheduled tasks found.")

    # Getting the version
    file_path = "C:\Program Files\SteelSeries\GG\SteelSeriesGG.exe"
    software_name = "SteelSeriesGG"
    version = get_file_version(file_path)
    print(f"File version: {version}")
    
    print("Printing installed programs")
    print("-" * 80)
    installed_programs = get_installed_programs()
    for program in installed_programs:
        cheese = "string"
        print(program)
    
    #print("\n\n")
    print("Services")
    #Section
    #list_services()

    product_name = "Google Chrome"

    print("\n\n")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Chrome&pubStartDate=2021-08-04T00:00:00.000&pubEndDate=2021-10-22T00:00:00.000"

    nvd_results = get_nvd_results(url)
    if nvd_results and 'vulnerabilities' in nvd_results:
        for cve_entry in nvd_results['vulnerabilities']: 
            test = "test1"   
            #Section
            print(cve_entry['cve']['id'])
            print("Published: " + cve_entry['cve']['published'])
            print("Last Modified: " + cve_entry['cve']['lastModified'])
            print("Description: " + cve_entry['cve']['descriptions'][0]['value'])
            #print("\n\n")
    else:
        print("No results found or encountered an error.")

    #print(path_to_file)
    #print(program_names)
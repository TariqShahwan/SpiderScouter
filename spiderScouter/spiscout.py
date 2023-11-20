import subprocess
from ping3 import ping , verbose_ping
import time
import pexpect
import re
from pwn import *
from urllib.parse import urlparse, parse_qs
import urllib.parse
import sys
import requests
import concurrent.futures
import itertools
import threading
import shutil
import os

red='\033[31m'
blue='\033[34m'
ending='\033[0m'

help_message='''

Options: 

-h , --help       Display brief information about the tool 
-u , --url        Target Url or host


Description: 

Spider Scouter is a Tool used for fuzzing subdirectories , Scanning a Web App and 
Testing  for commmand injection
in a target url 
'''

def display_ascii_art(ascii_art):
    terminal_width, _ = shutil.get_terminal_size()
    lines = ascii_art.split('\n')

    # Adjust the art based on terminal width
    for line in lines:
        print(blue+line[:terminal_width]+ending)

def check_input(argv=[], *a, **kw):
    if (sys.argv[1] == '-h' or sys.argv[1] == '--help'):  
        print(help_message)
        exit(0)
    elif (sys.argv[1] == '-u' or sys.argv[1] == '--url'):
       return sys.argv[2].lower()
    else:
       exit(0)

if os.geteuid() != 0:
    print("Spider Scouter uses ping which requires root privileges. Please execute with sudo or as root.")
    sys.exit(1)

try:
 url=check_input()
except:
 print('Usage: python spiscout [OPTION .... -h or --help for help / -u or --url for host name]')
 exit(0)

def separate_url(url):
    if "://" not in url:
        url = "http://" + url
    result = urlparse(url)
    protocol = result.scheme
    domain = result.netloc
    path = result.path
    arguments = parse_qs(result.query)
    return url,protocol, domain, path, arguments
# Example usage:

full_url,protocol,domain,path,arguments=separate_url(url)
url_without_path=protocol+"://"+domain+"/"
print(f'\n\nUrl: {full_url}\nProtocol: {protocol}\nDomain: {domain}\nPath: {path}\nParameters: {arguments}\n\n')
available_paths = []




############################ ping section ###################################

def ping_target(domain):
#  print(full_url)
 result = ping(domain)
#  verbose_result = verbose_ping(domain)
 return result

############### gobuster section (subdirectory enumeration) ################

def loading_animation():
    frames = [red+'L'+ending+'aunching '+blue+'S'+ending+'pider scouter  '+red+'/'+ending, 
              'l'+red+'A'+ending+'unching s'+blue+'P'+ending+'ider scouter  '+blue+'-'+ending,
              'la'+red+'U'+ending+'nching sp'+blue+'I'+ending+'der scouter  '+red+'\\'+ending, 
              'lau'+red+'N'+ending+'ching spi'+blue+'D'+ending+'er scouter  '+blue+'|'+ending, 
              'laun'+red+'C'+ending+'hing spid'+blue+'E'+ending+'r scouter  '+red+'/'+ending,
              'launc'+red+'H'+ending+'ing spide'+blue+'R'+ending+' scouter  '+blue+'-'+ending, 
              'launch'+red+'I'+ending+'ng spider '+blue+'S'+ending+'couter  '+red+'\\'+ending,
              'launchi'+red+'N'+ending+'g spider s'+blue+'C'+ending+'outer  '+blue+'|'+ending,
              'launchin'+red+'G'+ending+' spider sc'+blue+'O'+ending+'uter  '+red+'/'+ending]
    for frame in frames:
        print(frame, end='\r')
        time.sleep(0.4)

def pause_execution():
    while True:
        user_input = input("\n\nPress Enter to continue...")
        if user_input == '':
            break
######################### Command injection Section #################################


def run_command_injection(domain,path):

   cookie=input('''
Enter your Cookie Token/Session Cookie -> ''').strip()
 
   data= input('''
Enter your url parameter Data: 
Example : https://www.example.com/[PATH]?[PARAMETER]=[YOUR DATA] -> ''').strip()
   
   full_url_and_path=domain+'/'+path

   command = f"commix --url='{full_url_and_path}' --cookie='{cookie}' --data='{data}'"
  # Execute the command
   process = pexpect.spawn(command, encoding='utf-8')

   process.interact()

#####################################################################################
############################## subdirectory fuzzer ##################################
num_threads = 20
def fuzz_directory(directory):
    url = url_without_path + directory
    response = requests.get(url)
    if response.status_code != 404:
        return directory

def scanning_animation(stop_event):
    animation = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write('\rScanning ' + next(animation))
        sys.stdout.flush()
        time.sleep(0.1)

def fuzz_directories(wordlist_file):
    existing_directories = []
    with open(wordlist_file, "r") as f:
        wordlist = f.read().splitlines()

    stop_event = threading.Event()

    scanning_thread = threading.Thread(target=scanning_animation, args=(stop_event,))
    scanning_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        results = executor.map(fuzz_directory, wordlist)
        
        for result in results:
            if result:
                existing_directories.append(result)
                print(f"\n{blue}Found:{ending} {result}")

    if existing_directories:
        print("\n\nFound Directories:")
        print(blue+"\n".join(existing_directories)+ending)
    else:
        print("\n\nNo existing directories found from the wordlist.")

    stop_event.set()
    scanning_thread.join()
    pause_execution()

        
###################### Scanner Section ###########################
def run_scan(url):
    # Ensure the protocol is included in the URL
    if "://" not in url:
        url = "http://" + url

    # Get the URL components
    url_parts = urllib.parse.urlparse(url)

    # Check if Nikto is installed
    try:
        subprocess.run(["nikto", "-h"], capture_output=True)
    except FileNotFoundError:
        print("Nikto is not installed.")
        return

    # Run the Nikto scan and capture the output
    try:
        result = subprocess.Popen(["nikto", "-h", url],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        print("Error occurred while running Nikto:", e)
        return
    
    # Print the Nikto scan output in real-time
    while True:
        output = result.stdout.readline()
        if output == "" and result.poll() is not None:
            break
        if output:
            print(output.strip())
    print("Nikto scan finished with exit code", result.returncode)
    pause_execution()
###################################################################

try :
 loading_animation()
 if(ping_target(domain)):
 
 
 
 
 
 
 ############################# heading section ###############################
 
 
  ascii_art='''
  
################################################################################
#                                                                              #
#     _____       ____    __                       ____        __ _____        #
#    / ___/____  /  _/___/ /__  _____   __________/ __ \__  __/ /|__  /_____   #
#    \__ \/ __ \ / // __  / _ \/ ___/  / ___/ ___/ / / / / / / __//_ </ ___/   #
#   ___/ / /_/ // // /_/ /  __/ /     (__  ) /__/ /_/ / /_/ / /____/ / /       #
#  /____/ .___/___/\__,_/\___/_/     /____/\___/\____/\__,_/\__/____/_/        #
#      /_/                                                                     #
#                                                                              #
#                                                                              #
#                        - Spider Sc0ut3r v1.0 beta-                           #
#                            - By Tariq Shahwan -                              #
################################################################################
  '''
 
  heading='''

 Use -h or --help for guidance

 NOTE : Install the required libraries and tools from the requirements.txt file before running Spider Scouter

 NOTE : Your Input must be the same domain shown in Your browser With No Subdirectories
 Usage: python spiscout [OPTION.... -h --help -u --domain] "[ domain / URL Without Path]" 


 1.Run Basic Scanning
 
 2.Fuzz subdirectories
 
 3.Check for Command Injection
 
 4.Exit
 
 '''
 
 while True:

  display_ascii_art(ascii_art)
  

  print(heading)
 
 
 
 # ############################# options section ###############################
 
  user_input = input('''
Choose between options-> ''').strip()
  
  if(user_input == '1'):
   run_scan(full_url)

  elif(user_input == '2'):
    wordlist=input('Enter the path of your wordlist: ').strip()
    fuzz_directories(wordlist)
  
  elif(user_input == '3'):
   run_command_injection(full_url,path)
  
  elif(user_input == '4'):
     print("Bye !!!")
     break
  else:
     print('Invalid Option!!')
 
 else : 
    print("Invalid Hostname!!!\n***NOTE: Host name must be written in the following form: [domain name]  OR | [Domain / Host Without Path]***")
    exit(0)
except:
   print("Invalid Input!!!!!\nBye !!!")





########## for later improvement i will add directory traversal scanning #############
# def run_directory_traversal(domain):
#     path=input('''

# Enter the full URL path with the vulnerable parameter: 
# Example : https://www.example.com/[PATH]?[PARAMETER] -> ''').strip()
#     # command = f'dotdotpwn -m stdout -d 6 -f /etc/passwd'

#     print('''
    
# Directory Traversal Available payloads:
    
#     ''')
#     # Start the dotdotpwn process

#     # Wait for the process to prompt for input
#     for payload in payloads:
#        time.sleep(1)
#        print(path+payload+'\n\n')
#     # # Send Enter key press
#     # process.sendline('')

#     # # Read and print the output
#     # for line in process:
#     #     print(line.rstrip())

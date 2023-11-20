import subprocess

def check_dependency(tool_name):
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"{tool_name} is already installed.")
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False

def install_commix():
    try:
        subprocess.run(['apt-get', 'install', 'commix', '-y'], check=True)
        print("Commix installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install Commix.")

def install_nikto():
    try:
        subprocess.run(['apt-get', 'install', 'nikto', '-y'], check=True)
        print("Nikto installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install Nikto.")

def install_python_dependencies():
    try:
        subprocess.run(['pip', 'install', '-r', 'requirements.txt'], check=True)
        print("Python dependencies installed successfully.")
    except subprocess.CalledProcessError:
        print("Failed to install some of the Python dependencies.")

def main():
    missing_tools = []

    if not check_dependency('commix'):
        missing_tools.append('commix')

    if not check_dependency('nikto'):
        missing_tools.append('nikto')

    if missing_tools:
        print("The following tools are missing and will be installed:", missing_tools)
        for tool in missing_tools:
            if tool == 'commix':
                install_commix()
            elif tool == 'nikto':
                install_nikto()

    install_python_dependencies()

    # Continue with your tool execution or additional functionality
    # ...

if __name__ == "__main__":
    main()

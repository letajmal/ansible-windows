# Connecting Windows Server/Desktop as Ansible Host via SSH

This documentation outlines the steps to connect your Windows Server/Desktop to Ansible via SSH, allowing you to use it as an Ansible host.

1. [Installing SSH Server in Your Windows Machine](#1-installing-ssh-server-in-your-windows-machine)
2. [Connecting to Ansible Via Password Authentication](#2-connecting-to-ansible-via-password-authentication)
3. [Setting Up Passwordless Authentication](#3-setting-up-passwordless-authentication)
4. [Checking Connection and Running a Test Playbook](#4-checking-connection-and-running-a-test-playbook)

## 1. Installing SSH Server in Your Windows Machine

Follow these steps to install an SSH server on your Windows machine:

- Refer to [Microsoft's official documentation](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell#install-openssh-for-windows) for detailed instructions.
  
  Alternatively, you can follow the steps below:

  To make sure that OpenSSH is available, run the following cmdlet:
  ```powershell
  Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
  ```

  The command should return the following output if neither are already installed:
  ```powershell
  Name  : OpenSSH.Client~~~~0.0.1.0
  State : NotPresent

  Name  : OpenSSH.Server~~~~0.0.1.0
  State : NotPresent
  ```

  Then, install the server or client components as needed:
  ```powershell
  # Install the OpenSSH Client
  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0

  # Install the OpenSSH Server
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  ```

  Both commands should return the following output:
  ```powershell
  GPath          :
  Online        : True
  RestartNeeded : False
  ```

  To start and configure OpenSSH Server for initial use, open an elevated PowerShell prompt (right click, Run as an administrator), then run the following commands to start the sshd service:
  ```powershell
  # Start the sshd service
  Start-Service sshd

  # OPTIONAL but recommended:
  Set-Service -Name sshd -StartupType 'Automatic'

  # Confirm the Firewall rule is configured. It should be created automatically by setup. Run the following to verify
  
  if (!(Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue | Select-Object Name, Enabled)) {
      Write-Output "Firewall Rule 'OpenSSH-Server-In-TCP' does not exist, creating it..."
      New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
  } else {
      Write-Output "Firewall rule 'OpenSSH-Server-In-TCP' has been created and exists."
  }
  ```

## 2. Connecting to Ansible Via Password Authentication

Once the SSH server is installed, you can connect to Ansible using password authentication. Here's how:

- Open a terminal on your Ubuntu Linux Ansible Server.
- Create an inventory file with the following content. Replace `example.com` or `IP` with the actual IP address or domain of your Windows machine:

  ```ini
  [win]
  example.com or IP

  [win:vars]
  ansible_user=<user>
  ansible_password=<password>
  ansible_connection=ssh
  ansible_shell_type=powershell or cmd
  ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  ansible_ssh_retries=3
  ansible_become_method=runas
  ```

  Replace `<user>`, `<password>`, and other placeholders with your actual Windows username, password, and connection details.

- Save the inventory file.

- Use the following command to connect to your Windows machine:

  ```bash
  ansible all -i path/to/inventory/file -m win_ping
  ```

  Replace `path/to/inventory/file` with the actual path to your inventory file.

Now, you should be able to ping your Windows machine from the Ubuntu Linux Ansible Server using the specified inventory file.

Feel free to customize and adapt these instructions based on your specific environment and requirements.


Replace `<user>`, `<password>`, and other placeholders with your actual Windows username, password, and connection details.

## 3. Setting Up Passwordless Authentication

To configure the Windows SSH server with public key authentication, follow these steps:

1. Add your public key to the user's `.ssh/authorized_keys` folder on the Windows machine.

2. Disable password authentication in `ProgramData/ssh/sshd_config`:

    Open a PowerShell session as an administrator:

    ```powershell
    cd $env:PROGRAMDATA/ssh/
    notepad.exe sshd_config
    ```

    Update the following parameters in `sshd_config`:

    ```plaintext
    PasswordAuthentication no
    ```

    Enable public key authentication:

    ```plaintext
    PubkeyAuthentication yes
    ```

    Disable strict mode:

    ```plaintext
    StrictModes no
    ```

    Make sure `administrators_authorized_keys` is disabled:

    ```plaintext
    # Match Group administrators
    #    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
    ```

3. Run the following command to change the default SSH shell to PowerShell:

    ```powershell
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
    ```

4. Restart the sshd service:

    - You can restart the service from the `services.msc` console.
    - Alternatively, use PowerShell:

    ```powershell
    Restart-Service sshd
    ```

## 4. Checking Connection and Running a Test Playbook

Now that the Windows SSH server is configured for public key authentication, let's check the connection and run a test playbook.

1. Ensure that you have commented out the `ansible_password` variable in your inventory file.

2. Open a terminal on your Ubuntu Linux Ansible Server.

3. Use the following command to check the connection to your Windows machine:

    ```bash
    ansible all -i path/to/inventory/file -m win_ping
    ```

    Replace `path/to/inventory/file` with the actual path to your inventory file.

    If the connection is successful, you should receive a positive response.

4. Run a test playbook to verify further functionality. Create a playbook file (e.g., `playbook.yml`) with the following content:

    ```yaml
    - hosts: win
      gather_facts: no
      tasks:
        - name: test powershell
          win_shell: |
            whoami
          register: result_get_host

        - name: display result_get_host
          debug:
            var: result_get_host
    ```

5. Execute the test playbook using the following command:

    ```bash
    ansible-playbook -i path/to/inventory/file test_playbook.yml
    ```

    Replace `path/to/inventory/file` with the actual path to your inventory file.

    If everything is set up correctly, the playbook should run successfully, and you should see the username as output.

Congratulations! You have successfully configured your Windows machine as an Ansible host using SSH with public key authentication.

Feel free to customize and adapt these instructions based on your specific environment and requirements.




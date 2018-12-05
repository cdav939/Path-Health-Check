from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoAuthenticationException, NetMikoTimeoutException
from colorama import init
from colorama import Fore
import sys
import re
import getpass


class HealthCheck:
    """ health check - performs traceroute, ping test, and
        chosen commands on the devices on the path """

    def __init__(self):
        # variable initialization
        self.start_device, self.destination_device = self.ask_user_devices()
        self.trace_command = "traceroute " + self.destination_device
        self.logname = self.ask_user_for_log()
        self.print_screen = self.ask_user_if_print_to_screen()
        self.auto_run = self.ask_user_auto_run()
        self.user, self.password = self.user_credentials_prompt()
        self.traceroute_output = """ """
        self.network_device_param = {}
        self.net_connect = None
        self.hop_list = []
        self.command_list = []

        # log data
        self.log = {}

    def user_credentials_prompt(self):
        """ user credentials prompt """

        print("\nPlease type in your router credentials.")

        # user credential prompt
        user = input('User: ')
        password = getpass.getpass('Password: ')
        # secret = getpass.getpass('Secret: ')

        return user, password

    def ask_user_for_log(self):
        """ ask the user what the log file will be named """

        log_name = input("\nPlease enter a name for the log file: ")

        if log_name.endswith('.txt'):
            return log_name.strip()
        else:
            return log_name.strip() + '.txt'

    def user_verify(self, message, sev=0):
        """ takes input in form of string and optional severity value. Verifies
            whether user entered y or n"""

        # print in red if severity is 1
        if sev == 1:
            user_input = input(Fore.RED + message + Fore.WHITE)
        else:
            user_input = input(message)

        if user_input.lower() == 'y' or user_input.lower() == 'yes':
            return True
        else:
            return False

    def ask_user_if_print_to_screen(self):
        """ ask user if they want to print output to the screen too """

        return self.user_verify("\nPrint to the screen? (y/n) ")

    def ask_user_auto_run(self):
        """ ask user if they want to execute script in auto mode """

        return self.user_verify("\nWould you like to execute script in auto mode? (y/n) ")

    def validate_address(self, s):
        """ validates the address is valid IP or hostname (just abc char for now) """

        if s == "":
            return False

        if s[0].isalpha():
            return True

        a = s.split('.')
        if len(a) != 4:
            return False
        for x in a:
            if not x.isdigit():
                return False
            i = int(x)
            if i < 0 or i > 255:
                return False
        return True

    def ask_user_devices(self):
        """ ask user for starting device and destination device """

        start_device = input('Enter starting device address: ').strip(' ')

        while not self.validate_address(start_device):
            start_device = input(Fore.RED + "Please enter a valid IP address or hostname. Enter [q] to quit: "
                                 + Fore.WHITE).lstrip(' ')
            if start_device.lower() == 'q':
                sys.exit(0)

        destination_device = input('Enter destination device address: ').strip(' ')

        while not self.validate_address(destination_device):
            destination_device = input(Fore.RED + "Please enter a valid IP address or hostname. Enter [q] to quit: "
                                       + Fore.WHITE).lstrip(' ')
            if destination_device.lower() == 'q':
                sys.exit(0)

        return start_device, destination_device

    def display_trace_warning(self):
        """ warns user traceroute is about to run and asks if they want to proceed """

        if not self.auto_run:
            user_message = Fore.CYAN + "\nYou are about to trace the path from " + self.start_device.upper() + " to " \
                           + self.destination_device
            print(user_message)

            return self.user_verify("\nAre you sure you want to proceed? (y/n) ", 1)

        return True

    def display_commands_warning(self):
        """ warns user list of commands are about to run and asks if they want to proceed """

        if not self.auto_run:
            user_message = Fore.CYAN + "\nYou are about to run the following commands:"
            print(user_message)

            for command in self.command_list:
                print(command)

            print(Fore.CYAN + "\nOn the following devices:")
            for hop in self.hop_list:
                print(hop)

            return self.user_verify("\nAre you sure you want to proceed? (y/n) ", 1)

        return True

    def run_traceroute(self):
        """ run traceroute method that runs the initial traceroute command on
        the starting network device """

        print(Fore.CYAN + "\nRunning traceroute from " + self.start_device.upper() + " to " +
              self.destination_device.upper() + Fore.WHITE)

        while True:
            # noinspection PyBroadException
            try:
                # build the appropriate device parameters for netmiko
                self.network_device_param = {
                    'device_type': 'cisco_ios',
                    'ip': self.start_device,
                    'username': self.user,
                    'password': self.password,
                    'port': 8181,
                    'verbose': False,
                }

                # initialize the connect handler of netmiko
                self.net_connect = ConnectHandler(**self.network_device_param)

            except NetMikoAuthenticationException:
                print("Unable to login")
                self.user, self.password = self.user_credentials_prompt()
                continue
            except NetMikoTimeoutException:
                print("Connection Timeout")
                self.start_device, self.destination_device = self.ask_user_devices()
                continue
            except Exception:
                print("Unexpected Error")
                sys.exit(1)

            # enter enable mode if required
            if self.net_connect.find_prompt().endswith('>'):
                self.net_connect.enable()

            # generate log data structure if key does not exist
            self.log[self.start_device] = ''

            # otherwise assume a normal show command
            out = self.net_connect.send_command(self.trace_command)

            # add to log
            self.log[self.start_device] += '\n\n' + self.start_device + "# " + self.trace_command + "\n"
            self.log[self.start_device] += out

            self.traceroute_output = out

            # print the show command output
            if self.print_screen:
                user_message = Fore.MAGENTA + "\nRUNNING: " + Fore.WHITE + self.trace_command
                print(user_message)
                print(out)

            return self.traceroute_output

    def traceroute_parse(self, traceroute_string):

        traceroute_text = traceroute_string

        trace_route = []
        ip_list = []
        new_output = traceroute_text.split('\n')

        for line in new_output:
            line_output = list(filter(None, filter(None, line.split(' '))))
            if len(line_output) != 0 and bool(re.search(r'^\d', line_output[0])):
                if not (bool(re.search(r'\D', line_output[0]))):
                    trace_route.append(line_output)
                    ip_list.append(line_output[1])
                else:
                    alt = ["alt"] + line_output
                    trace_route.append(alt)

        final_route = [v for v in trace_route if not (v[0] == "alt" and v[1] in ip_list)]

        return final_route

    def ping_test(self, route_table):

        hops = route_table
        round_trip = []

        for i in hops:
            if i[1] == '*':
                print("Hop " + str(hops.index(i) + 1) + " . . . not able to trace")
            else:
                for index, item in enumerate(i):
                    if item == "ms" or item == "msec":
                        round_trip.append(i[index - 1])
                    elif bool(re.search(r'[ms]|[msec]', item)):
                        round_trip.append(item.strip("ms"))
                average = list(map(float, round_trip))
                average = sum(average)/len(average)
                print("Hop " + str(hops.index(i) + 1) + " IP address: " + i[1] + " - - - Avg. RTT: " + str('%.3f'
                                                                                                    % average) + "ms")
                self.hop_list.append(i[1])

        print("\nHOP LIST:")

        for hop in self.hop_list:
            print(hop)

        if not self.auto_run:
            ping_action = input("\nAbout to ping hops. Press [Enter] to ping devices along path.\n"
                                "Add [a] or remove [r] devices. Skip [s] to more tests. ")

            # user add devices
            if ping_action.lower() == 'a':
                while True:
                    add_device = input("Enter additional device to ping or [Enter] to continue [q] to quit. : ").strip(' ')
                    if add_device == '':
                        break
                    if add_device.lower() == 'q':
                        sys.exit(0)
                    while not self.validate_address(add_device):
                        add_device = input(Fore.RED + "Please enter a valid IP address or hostname. "
                                                      "[Enter] to continue [q] to quit: " + Fore.WHITE).strip(' ')
                        if add_device.lower() == 'q':
                            sys.exit(0)
                        if add_device == '':
                            break
                    if add_device == '':
                        break
                    if add_device in self.hop_list:
                        print(Fore.RED + "Device already in list." + Fore.WHITE)
                    else:
                        self.hop_list.append(add_device)

            # user remove devices
            elif ping_action.lower() == 'r':
                while True:
                    remove_device = input("Remove devices from ping test or [Enter] to continue [q] to quit : ").strip(' ')
                    if remove_device == '':
                        break
                    elif remove_device.lower() == 'q':
                        sys.exit(0)
                    elif remove_device in self.hop_list:
                        self.hop_list.remove(remove_device)
                    else:
                        print(Fore.RED + "Device not in list.  " + Fore.WHITE)

            # skip ping test
            elif ping_action.lower() == 's':
                return

            print('\n')

        # enter enable mode if required
        if self.net_connect.find_prompt().endswith('>'):
            self.net_connect.enable()

        for hop in self.hop_list:
            out = self.net_connect.send_command("ping " + hop)
            if self.print_screen:
                print(out)

        # close existing ssh session
        self.net_connect.disconnect()

    def ask_user_commands(self):
        """ assumes two basic commands to run on devices and user can add or remove commands """

        self.command_list = ['show ip interface brief',
                             'show module']

        if not self.auto_run:
            while True:
                print(Fore.CYAN + "\nAbout to run following commands on all hops:" + Fore.WHITE)
                for command in self.command_list:
                    print(command)

                commands_action = input("\nType new command to add command or existing command to remove.\n"
                                        "[Enter] to continue, [q] to quit: ")
                if commands_action == '':
                    return self.command_list
                elif commands_action.lower() == 'q':
                    sys.exit(0)
                elif commands_action in self.command_list:
                    self.command_list.remove(commands_action)
                else:
                    self.command_list.append(commands_action)

    def run_commands(self, commands):
        """ automatically runs the commands on the devices from the traceroute """

        for hop in self.hop_list:
            user_message = "\nRunning commands on " + hop.upper()
            print(Fore.CYAN + user_message + Fore.WHITE)

            self.network_device_param = {
                'device_type': 'cisco_ios',
                'ip': hop,
                'username': self.user,
                'password': self.password,
                #'port': 8181,
                'verbose': False,
            }

            self.log[hop] = ''

            # noinspection PyBroadException
            try:
                # initialize the connect handler of netmiko
                net_connect = ConnectHandler(**self.network_device_param)

            except NetMikoAuthenticationException:
                print("Unable to login with credentials")
                self.log[hop] += "\n\nUnable to login with credentials"
                continue
            except NetMikoTimeoutException:
                print("Connection Timeout")
                self.log[hop] += "\n\nConnection Timeout"
                continue
            except Exception:
                print("Unexpected Error")
                self.log[hop] += "\n\nUnexpected Error"
                continue

            # enter enable mode if required
            if net_connect.find_prompt().endswith('>'):
                net_connect.enable()

            # iterate through the commands list
            for line in commands:

                # otherwise assume a normal show command
                out = net_connect.send_command(line.strip())

                # add to log
                self.log[hop] += '\n\n' + hop + "# " + line.strip() + "\n"
                self.log[hop] += out

                # print the show command output
                if self.print_screen:
                    user_message = Fore.MAGENTA + "\nRUNNING: " + Fore.WHITE + line.strip()
                    print(user_message)
                    print(out)

            # close existing ssh session
            net_connect.disconnect()

    def write_log(self):
        """ write log to output file """

        with open(self.logname, 'w') as fn:

            for device, logdata in self.log.items():
                # header information
                fn.write("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                fn.write("Source Device: " + device + "\n")
                fn.write("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

                # write actual log data
                for line in logdata.splitlines():
                    fn.write(line + '\n')

                fn.write('\n')


def main():
    """ main function to run script """

    # initialize colorama
    init(autoreset=True)

    print(Fore.YELLOW + "# Path Health Check\n")

    # initialize script
    hc_script = HealthCheck()

    # run traceroute and ping test if user agrees
    if hc_script.display_trace_warning():
        traceroute_out = hc_script.run_traceroute()
        traceroute_tab = hc_script.traceroute_parse(traceroute_out)
        hc_script.ping_test(traceroute_tab)
    else:
        print("Not proceeding.")
        sys.exit(0)

    # ask user commands to run
    commands_to_run = hc_script.ask_user_commands()

    # run commands on devices if user agress
    if hc_script.display_commands_warning():
        hc_script.run_commands(commands_to_run)
        hc_script.write_log()
    else:
        print("Not proceeding.")
        sys.exit(0)

    # pauses the script at the end to state message
    input("\nComplete!")


if __name__ == '__main__':
    main()

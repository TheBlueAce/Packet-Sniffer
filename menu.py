import sniffer
import os

def main_menu():
    
    def clear_terminal():
        os.system('cls' if os.name == 'nt' else 'clear')

    
    def sniffer_settings_menu():
        
        while True:
            clear_terminal()
            print("Sniffer Settings")
            print("----------------")
            print(f"1. Packet count       : {packet_sniffer.count}")
            print(f"2. Duration (seconds) : {packet_sniffer.duration}")
            print(f"3. Packet logging     : {packet_sniffer.packet_logging}")
            print(f"4. Terminal logging   : {packet_sniffer.terminal_logging}")
            print("5. Back to main menu\n")

            choice = input("What would you like to change? ")
            if choice == "1":
                packet_sniffer.count = int(input("Enter new packet count (0 for infinite): "))
            elif choice == "2":
                packet_sniffer.duration = int(input("Enter new duration in seconds (0 for infinite): "))
            elif choice == "3":
                packet_sniffer.packet_logging = not(packet_sniffer.packet_logging)
                print(f"Packet logging toggled to {packet_sniffer.packet_logging}")
            elif choice == "4":
                packet_sniffer.terminal_logging = not(packet_sniffer.terminal_logging)
                print(f"Terminal logging toggled to {packet_sniffer.terminal_logging}")
            elif choice == "5" or choice.lower() == "q":
                break
            else:
                print("Invalid input! Try again.")
                
            input("\nPress Enter to continue...")

    def file_format_menu():
        while True:
            clear_terminal()
            print("Choose output file format")
            print("--------------------------")
            print("1. .txt")
            print("2. .csv")
            print("3. .pcap\n")
            print("4. Back to main menu")
            choice = input("Select format: ")
            if choice == "1":
                packet_sniffer.ext = ".txt"
            elif choice == "2":
                packet_sniffer.ext = ".csv"
            elif choice == "3":
                packet_sniffer.ext = ".pcap"
            elif choice == "4" or choice.lower() == "q":
                break
            else:
                print("Invalid choice, try again!")
                
            print(f"File format is {packet_sniffer.ext}")
            input("\nPress Enter to continue...")

    def view_files_menu():
        clear_terminal()
        print("Files Created This Session")
        print("--------------------------")
        if not files_created:
            print("No files created yet.")
        else:
            for f in files_created:
                print(f" - {f}")
        input("\nPress Enter to return...")

    
    packet_sniffer = sniffer.PacketSniffer(count=0, duration=10, packet_logging=True, terminal_logging=False)
    files_created = []

    # This is the actual menu sorry for readability being a lil messed up
    while True:
        clear_terminal()
        print("Welcome to my Packet Sniffer! What would you like to do?")
        print("--------------------------------------------------------")
        print("1. Start Sniffing!")
        print("2. Sniffer Settings")
        print("3. File Format")
        print("4. View Files Created")
        print("5. Quit\n")

        try:
            user_input = (input("I would like to... "))
            
            if user_input.lower() == "q":
                print("Thanks for stopping by!")
                break
            
            if user_input == "1":
                packet_sniffer.start()
                if packet_sniffer.packet_logging and packet_sniffer._prev_file not in files_created:
                    files_created.append(packet_sniffer._prev_file)
                else:
                    print("No log file created (logging off). Make sure to turn it on if this is a mistake!")
                input("\nPress Enter to continue...")

            elif user_input == "2":
                sniffer_settings_menu()

            elif user_input == "3":
                file_format_menu()

            elif user_input == "4":
                view_files_menu()

            elif user_input == "5" or user_input.lower() == "q":
                print("Thanks for stopping by!")
                break

            else:
                print("Please enter a number between 1 and 5 or q to quit.")
                input("\nPress Enter to continue...")

        except ValueError:
            print("Please enter a valid integer.")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    main_menu()

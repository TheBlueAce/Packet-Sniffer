import sniffer

def main_menu():
    
    while True:
        try:
            print("Welcome to my Packet Sniffer! What would you like to do?")
            print("--------------------------------------------------------")
            print()
            print("1. Start Sniffing!")
            print("2. Sniffer Settings")
            print("3. File Format")
            print("4. View Files created")
            print("5. Quit!")
            user_input = int(input("I would like to... "))
            if user_input == 1:
                sniffer.packet_sniffer()
                
            elif user_input in [2,3,4]:
                print()
            elif user_input == 5:
                break
            
            else:
                raise ValueError
            
        except ValueError:
            print(f"Try typing integers in range of 1 - 5!")
            
main_menu()
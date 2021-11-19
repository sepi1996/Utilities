import socket
import re
import ipaddress

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_pattern = re.compile("([0-9]+)")

open_IPs = []

while True:
    port_entered = input("\nPuerto a escanerar: ")
    if port_pattern.search(port_entered):
        print(f"{port_entered} es valido")
        break


print("Rango de IPs a escanear: <IP>\<subnet> (ex would be 192.168.0.0/24)")
ip_entered = input("Enter IP range: ")
subnet = ipaddress.ip_network(ip_entered, False)


for ip in subnet.hosts():
    try:
        print(f"Escaneando {ip} al puerto {port_entered}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((str(ip), int(port_entered)))
            open_IPs.append(str(ip))
    except Exception as e:
        pass

for ip in open_IPs:
    print(f"{port_entered} esta abierto en {ip}")


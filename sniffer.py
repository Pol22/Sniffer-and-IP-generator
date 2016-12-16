import socket
import threading
import struct
import os
from tkinter import *
from tkinter import ttk
from tkinter import font

ip_header = ["Version", "Header size", "Size", "ID", "Flags", "Offset",
             "TTL", "Protocol", "Checksum", "Source IP", "Destination IP"]


def string_to_udp_data(str):
    udp_header = struct.unpack("!HHHH", str[:8])
    package = {"Source port": udp_header[0],
               "Destination port": udp_header[1],
               "Length": udp_header[2],
               "Checksum": udp_header[3],
               "Data": str[8:].decode('utf', 'ignore')}
    return package


def string_to_tcp_data(str):
    tcp_header = struct.unpack("!HHIIHHHHI", str[:24])
    package = {"Source port": tcp_header[0],
               "Destination port": tcp_header[1],
               "Number": tcp_header[2],
               "Acknowledgment number": tcp_header[3],
               "Header length": tcp_header[4] >> 12,
               "Reserved": (tcp_header[4] & 0x0F00) >> 9,
               "Flags": (tcp_header[4] & 0b0000000111111111),
               "Window size": tcp_header[5],
               "Checksum": tcp_header[6],
               "Urgent": tcp_header[7],
               "Options": tcp_header[8],
               "Data": str[24:].decode('utf', 'ignore')}
    return package


def string_to_icmp_data(str):
    icmp_header = struct.unpack("!BBH", str[:4])
    package = {"Type": icmp_header[0],
               "Code": icmp_header[1],
               "Checksum": icmp_header[2],
               "Data": str[4:].decode('utf', 'ignore')}
    return package


class Sniffer:
    def __init__(self, master):
        self.package_list = list()
        # socket
        self.HOST = socket.gethostbyname(socket.gethostname())
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                  socket.IPPROTO_IP)
        self.sock.bind((self.HOST, 0))
        # Include IP headers
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # receive all packages
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        # start button
        self.start_button = Button(master, text="Start", command=self.start,
                                   font=16)
        self.start_button.place(x=5, y=5, height=30, width=50)
        # break button
        self.break_button = Button(master, text="Stop", command=self.stop,
                                   font=16)
        self.break_button.place(x=60, y=5, height=30, width=50)

        self.connect_checker = Radiobutton(master, text="", variable=1,
                                           fg="red")
        self.connect_checker.place(x=120, y=5)

        self.kill = False
        self.filt_IP = ""
        self.filt_Prot = 0

        # filter
        self.filter_IP_label = Label(master, text="Filtered IP", font=16)
        self.filter_IP_label.place(x=5, y=35, height=30, width=70)
        self.filtered_IP = Text(master, font=16)
        self.filtered_IP.place(x=80, y=40, height=22, width=200)
        self.filtered_IP.delete(1.0, END)

        self.filter_Prot_label = Label(master, text="Filtered Protocol",
                                       font=16)
        self.filter_Prot_label.place(x=285, y=35, height=30, width=120)
        self.filtered_Prot = Text(master, font=16)
        self.filtered_Prot.place(x=410, y=40, height=22, width=100)
        self.filtered_Prot.delete(1.0, END)

        self.accept_filter = Button(master, text="Accept filter",

                                    command=self.accept_filt, font=16)
        self.accept_filter.place(x=515, y=35, height=30, width=100)

        container = ttk.Frame()
        container.place(x=0, y=80, height=250, width=800)

        self.tree = ttk.Treeview(columns=ip_header, show="headings")
        vsb = ttk.Scrollbar(orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(column=0, row=0, sticky='nsew', in_=container)
        vsb.grid(column=1, row=0, sticky="ns", in_=container)
        hsb.grid(column=0, row=1, sticky='ew', in_=container)

        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        for col in ip_header:
            self.tree.heading(col, text=col.title().upper())
            self.tree.column(col, width=font.Font().measure(col.title()))

        self.tree.bind("<Double-1>", self.OnDoubleClick)

        # package Label
        self.package_info = Label(master, text="INFO", font=12, anchor='nw',
                                  justify="left")
        self.package_info.place(x=0, y=335, height=465, width=800)

    def OnDoubleClick(self, event):
        item = self.tree.selection()
        id_package = self.tree.item(item)['values'][3]
        checksum_package = self.tree.item(item)['values'][8]
        for item in self.package_list:
            if(item["ID"] == id_package and
               item["Header Checksum"] == checksum_package):
                self.package_info["text"] = '''IP Header:
                Version: {0}, Header size: {1}, Size: {2}, ID: {3}, Flags: {4},
                Offset: {5}, TTL: {6}, Protocol: {7}, Header Checksum: {8:X},
                Source IP: {9}, Destination IP: {10}
                '''.format(item["Version"], item["Header size"], item["Size"],
                           item["ID"], item["Flags"], item["Offset"],
                           item["TTL"], item["Protocol"],
                           item["Header Checksum"], item["Source IP"],
                           item["Destination IP"])
                if(item["Protocol"] == 17):
                    udp_pack = string_to_udp_data(item["Data"])
                    self.package_info["text"] += '''
UDP Header:
                Source port: {0}, Destination port: {1},
                Length: {2}, Checksum: {3:X},
                Data: {4}'''.format(udp_pack["Source port"],
                                    udp_pack["Destination port"],
                                    udp_pack["Length"],
                                    udp_pack["Checksum"], udp_pack["Data"])
                elif(item["Protocol"] == 6):
                    try:
                        tcp_pack = string_to_tcp_data(item["Data"])
                        self.package_info["text"] += '''
TCP Header:
                Source port: {0}, Destination port: {1},
                Number: {2},
                Acknowledgment number: {3},
                Header length: {4}, Reserved: {5}, Flags : {6},
                Window size: {7},
                Checksum: {8:X}, Urgent: {9},
                Options: {10},
                Data: {11}'''.format(tcp_pack["Source port"],
                                     tcp_pack["Destination port"],
                                     tcp_pack["Number"],
                                     tcp_pack["Acknowledgment number"],
                                     tcp_pack["Header length"],
                                     tcp_pack["Reserved"], tcp_pack["Flags"],
                                     tcp_pack["Window size"],
                                     tcp_pack["Checksum"], tcp_pack["Urgent"],
                                     tcp_pack["Options"], tcp_pack["Data"])
                    except:
                        self.package_info["text"] += '''
TCP Header:
                Data: {0}'''.format(item["Data"].decode('utf', 'ignore'))
                elif(item["Protocol"] == 1):
                    icmp_pack = string_to_icmp_data(item["Data"])
                    self.package_info["text"] += '''
ICMP Header:
                Type: {0}, Code: {1}, Checksum: {2:X},
                Data: {3}'''.format(icmp_pack["Type"], icmp_pack["Code"],
                                    icmp_pack["Checksum"],
                                    icmp_pack["Data"])
                else:
                    self.package_info["text"] += '''
Data: {0}'''.format(item["Data"].decode('utf', 'ignore'))
                break

    def accept_filt(self):
        self.tree.delete(*self.tree.get_children())
        filt_IP = str(self.filtered_IP.get(1.0, END)).replace('\n', '')
        self.filt_IP = filt_IP
        filt_Prot_str = str(self.filtered_Prot.get(1.0, END)).replace('\n', '')
        if filt_Prot_str == '':
            self.filt_Prot = filt_Prot = 0
        else:
            self.filt_Prot = filt_Prot = int(filt_Prot_str)
        for packet in self.package_list:
            if ((packet["Source IP"] == filt_IP or
                packet["Destination IP"] == filt_IP or filt_IP == '') and
               (packet["Protocol"] == filt_Prot or filt_Prot == 0)):
                    packeti = (packet["Version"], packet["Header size"],
                               packet["Size"], packet["ID"],
                               packet["Flags"], packet["Offset"],
                               packet["TTL"], packet["Protocol"],
                               packet["Header Checksum"], packet["Source IP"],
                               packet["Destination IP"])
                    self.tree.insert('', 'end', values=packeti)
            else:
                self.package_list.remove(packet)

    def get_packages(self):
        while not self.kill:
            data = self.sock.recv(65565)
            ip_header = struct.unpack("!BBHHHBBH4s4s", data[:20])
            if ip_header[6] != self.filt_Prot and self.filt_Prot != 0:
                continue
            version = ip_header[0] >> 4
            head_size = ip_header[0] & 0x0F
            destinationIP = socket.inet_ntoa(ip_header[-1])
            sourceIP = socket.inet_ntoa(ip_header[-2])
            packet = dict()
            packet["Version"] = version
            packet["Header size"] = head_size
            packet["Size"] = ip_header[2]
            packet["ID"] = ip_header[3]
            packet["Flags"] = ip_header[4] >> 13
            packet["Offset"] = ip_header[4] & 0x1FFF
            packet["TTL"] = ip_header[5]
            packet["Protocol"] = ip_header[6]
            packet["Header Checksum"] = ip_header[7]
            packet["Source IP"] = sourceIP
            packet["Destination IP"] = destinationIP
            packet["Data"] = data[20:]
            packeti = (packet["Version"],
                       packet["Header size"], packet["Size"], packet["ID"],
                       packet["Flags"], packet["Offset"], packet["TTL"],
                       packet["Protocol"], packet["Header Checksum"],
                       packet["Source IP"], packet["Destination IP"])
            if ((packet["Source IP"] == self.filt_IP or
                packet["Destination IP"] == self.filt_IP) or
               self.filt_IP == ""):
                    self.package_list.append(packet)
                    self.tree.insert('', 'end', values=packeti)

    def start(self):
        self.kill = False
        self.connect_checker["fg"] = "green"
        self.package_list.clear()
        self.tree.delete(*self.tree.get_children())
        th = threading.Thread(target=self.get_packages, args=())
        th.daemon = True
        th.start()

    def stop(self):
        self.kill = True
        self.connect_checker["fg"] = "red"

    def close(self):
        root.destroy()
        self.kill = True
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        root.quit()


if __name__ == '__main__':
    root = Tk()
    sniffer = Sniffer(root)
    root.minsize(width=800, height=700)
    root.wm_title("Sniffer")
    root.protocol('WM_DELETE_WINDOW', sniffer.close)
    root.mainloop()

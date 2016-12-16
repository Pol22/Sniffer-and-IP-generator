import socket
from tkinter import *
from tkinter import ttk
from tkinter import messagebox


class Generator_IP(object):
    def __init__(self, master):
        self.src_ip = Label(master, text="Source IP:", font=16)
        self.src_ip.place(x=35, y=5, height=30, width=70)
        self.src_ip_txt = Text(master, font=16)
        self.src_ip_txt.place(x=110, y=10, height=22, width=200)
        self.src_ip_txt.delete(1.0, END)

        self.dst_ip = Label(master, text="Destination IP:", font=16)
        self.dst_ip.place(x=5, y=35, height=30, width=100)
        self.dst_ip_txt = Text(master, font=16)
        self.dst_ip_txt.place(x=110, y=40, height=22, width=200)
        self.dst_ip_txt.delete(1.0, END)

        self.data_label = Label(master, text="DATA:", font=16)
        self.data_label.place(x=56, y=65, height=30, width=50)
        self.data_txt = Text(master, font=16)
        self.data_txt.place(x=110, y=70, height=22, width=284)
        self.data_txt.delete(1.0, END)

        self.get_ip_button = Button(master, text="GET IP", command=self.get_IP)
        self.get_ip_button.place(x=315, y=5, height=30, width=80)

        self.generate_button = Button(master, text="GENERATE",
                                      command=self.generate,
                                      font="TimeNewRomans, 40", fg="RED")
        self.generate_button.place(x=5, y=100, height=195, width=390)

    def get_IP(self):
        source_ip = socket.gethostbyname(socket.gethostname())
        self.src_ip_txt.delete(1.0, END)
        self.src_ip_txt.insert(1.0, source_ip)

    def generate(self):
        source_ip = str(self.src_ip_txt.get(1.0, END)).replace('\n', '')
        dest_ip = str(self.dst_ip_txt.get(1.0, END)).replace('\n', '')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_IP)
            s.bind((source_ip, 0))
            s.connect((dest_ip, 0))
            data = str(self.data_txt.get(1.0, END)).replace('\n', '')
            s.send(data.encode('utf'))
        except:
            messagebox.showerror("Socket error", "Cant create package")

    def close(self):
        root.destroy()
        root.quit()


if __name__ == '__main__':
    root = Tk()
    genner = Generator_IP(root)
    root.minsize(width=400, height=300)
    root.wm_title("IP generator")
    root.protocol('WM_DELETE_WINDOW', genner.close)
    root.mainloop()

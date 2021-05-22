# -*- coding: utf-8 -*-
"""
Created on Sun Apr 18 22:40:19 2021

@author:Naveen Kumar Vasudevan, 
        Doctoral Candidate, 
        The Xi Research Group, 
        Department of Chemical Engineering,
        McMaster University, 
        Hamilton, 
        Canada.
        
        naveenovan@gmail.com
        https://naveenovan.wixsite.com/kuroonai
"""

import os
from collections import OrderedDict
from tkinter import ttk
import tkinter as tk

wifis = os.popen('netsh wlan show profile').read().split('\n')
ssids = [x.split(':')[1] for x in wifis if ':' in x]

pwd={}
for ssid in ssids:
    if ssid != '':
        ssid = ssid.lstrip(' ')
        encrypted = False
        ssidinfo =  os.popen(f'netsh wlan show profile name={ssid} key=clear').read().split('\n')
        #print(f'netsh wlan show profile name={ssid} key=clear')
        
        if len(ssidinfo) <3 : 
            ssidinfo=os.popen(f'netsh wlan show profile name=\"{ssid}\" key=clear').read().split('\n')
            
        for attributestart, attribute in enumerate(ssidinfo):
            if 'Authentication' in attribute and 'WPA2-Enterprise' in attribute:
                pwd.update({ssid : 'Encrypted - not available'})
                encrypted = True
                break

        if encrypted != True:
            for attributestop, attribute in enumerate(ssidinfo):
                if 'Key Content' in attribute:
                    pwd.update({ssid : ssidinfo[attributestop].split(': ')[1]})
                    break
                
passwords = OrderedDict(sorted(pwd.items()))
pwds = [list(x) for x in passwords.items()]
ssidslist, pwdslist = list(zip(*pwds))[0], list(zip(*pwds))[1]

col1max = len(max(ssidslist, key = len))
col2max = len(max(pwdslist, key = len))

rows = len(pwds)
   
# Creating tkinter win
win = tk.Tk()
win.title("Kuroonai's Wi-Fi password revealer")
win.resizable(width = 1, height = 1)

tview = ttk.Treeview(win, selectmode ='browse')
tview.pack(side ='left')
verscrlbar = ttk.Scrollbar(win, orient ="vertical", command = tview.yview)
verscrlbar.pack(side ='left', fill ='x')

tview.configure(xscrollcommand = verscrlbar.set)
tview["columns"] = ("1", "2", "3")
tview['show'] = 'headings'
  
tview.column("1", width = 50, anchor ='c')
tview.column("2", width = 200, anchor ='sw')
tview.column("3", width = 200, anchor ='sw')

tview.heading("1", text ="S.No.")
tview.heading("2", text ="SSID")
tview.heading("3", text ="Password")
  

for i in range(rows):
    tview.insert("", 'end', text =f"L{i+1}", 
                 values =(f"{i+1}", f"{pwds[i][0]}", f"{pwds[i][1]}"))

win.mainloop()

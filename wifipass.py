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
import PySimpleGUI as sg
import csv
from datetime import datetime
# data to be written row-wise in csv fil




# from tkinter import ttk
# import tkinter as tk

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

rows = range(1,len(pwds)+1)
for p,r in zip(pwds,rows):
    p.insert(0,str(r))

layout = [
    [sg.Table(values=pwds, key='table',font=('',14),
              headings=['S.No.', 'SSID','passwords'],
              display_row_numbers=False,justification='left',
              auto_size_columns=True,
              num_rows=min(100, len(pwds)))],
    [sg.In(size=(40, 1), enable_events=True, key="Folder"),
             sg.FolderBrowse('Save table'), sg.Button('Done', key='-done-')],

    [sg.Text(size=(60, 2), key="savedloc", text_color='black')], 
]

window = sg.Window("Kuroonai's Wi-Fi password revealer", layout, icon='logo.ico', grab_anywhere=False)



while True:
        event, values = window.read()
        
        if event == "Exit" or event == sg.WIN_CLOSED or event == '-done-':
            break
        
        elif event == "table":
            pass
        
        elif event == 'Folder':
            
            try:
                os.chdir(values['Folder'])
                header = ['S.No.', 'SSID', 'Passwords']
                with open(f'WiFi pass-{datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p")}.csv',\
                            'a+', newline ='') as file:
     
                    write = csv.writer(file)
                    write.writerow(header)
                    write.writerows(pwds)
    
                window['savedloc'].update(f"File saved at {values['Folder']} as WiFi pass-{datetime.now().strftime('%Y_%m_%d-%I_%M_%S_%p')}.csv'")
            except:
                pass
              
            
            
window.close()

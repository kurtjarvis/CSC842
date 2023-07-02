#!/usr/bin/env python3
# 
# Author: Kurt Jarvis
# Created: 02 July 2023
# Class: CSC-842
# Purpose: A msfvenom gui that rides on top of PyQt5

import sys, subprocess
from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QFrame, QMainWindow, QProgressBar, QDialog, QLabel, QVBoxLayout, QWidget, QComboBox, QDialogButtonBox
from PyQt5.QtWidgets import QFormLayout, QLineEdit, QPushButton, QMessageBox, QListView
# by using QSettings, this saves in the right spot regardless of windows, mac, or linux
from PyQt5.QtCore import QSettings, QTimer, QThread, QRegExp
from PyQt5.QtGui import QRegExpValidator, QStandardItem, QStandardItemModel

# Splash screen to add some pizazz to the loader
class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('MSFVenom GUI Builder Splash Screen')
        self.setFixedSize(1100, 500)
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.SplashScreen)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.n = 100
        self.counter = 0
        # If I was using the QT Designer, I'd just load the ui here
        self.initUI()
        # so at this point the splash screen is ready, now it just needs information on when it is updating its progress bar
        # put that in a timer loop to asynchronously go back an keep checking
        self.timer = QTimer()
        self.timer.timeout.connect(self.loading)
        self.timer.start(1)

    def initUI(self):
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        self.frame = QFrame()
        self.frame.setObjectName('kickoff')

        layout.addWidget(self.frame)
        # Create Labels
        self.labelTitle = QLabel(self.frame)
        self.labelTitle.setObjectName('LabelTitle')
        self.labelDesription = QLabel('<strong>MSFVenom GUI Builder Splash Screen</strong>', self.frame)
        self.labelDesription.setObjectName('LabelDesc')
        self.labelDesription.resize(self.width()-10, 50)
        self.labelDesription.move(0, 40)
        self.labelDesription.setAlignment(QtCore.Qt.AlignCenter)
        # Create progress bar
        self.progressbar = QProgressBar(self.frame)
        self.progressbar.resize(self.width() - 200 - 10, 50)
        self.progressbar.move(100, self.labelDesription.y() + 130)
        self.progressbar.setAlignment(QtCore.Qt.AlignCenter)
        self.progressbar.setFormat('%p%')
        self.progressbar.setTextVisible(True)
        self.progressbar.setRange(0, self.n)
        self.progressbar.setValue(self.counter)
        # Create progress bar label
        self.labelLoading = QLabel(self.frame)
        self.labelLoading.resize(self.width() - 10, 50)
        self.labelLoading.move(0, self.progressbar.y() + 70)
        self.labelLoading.setAlignment(QtCore.Qt.AlignCenter)
        self.labelLoading.setText('initializing...')
        self.labelLoading.setObjectName('LabelLoading')

    # so we made progress, update the gui and wait for further updates
    def updateProgress(self, label):
        self.labelLoading.setText('<strong>' + label + '</strong>')
        self.counter = int(self.counter) + 20
    
    # We will just keep updating the progress bar until it is full
    # If this should close when complete, then uncomment the line
    def loading(self):
        self.progressbar.setValue(self.counter)
        if self.counter >= self.n:
            self.timer.stop()
            #self.close()


class MainWindow(QWidget):
    def __init__(self, splash):
        
        super().__init__()
        self.setWindowTitle("MSFVenom Creator Box")

        self.settings = QSettings("artilleryRed", "msfvenom-gui")    
       
        # Create a QComboBox
        self.cbPayloads = QComboBox(self)
        self.cbPayloads.currentIndexChanged.connect(self.on_cbPayloads_changed)
        # read in the option list
        splash.updateProgress("Reading Payloads")
        payloads = self.readInOptions("payload")
        self.splitPayloads(payloads, self.cbPayloads)

        # Create a QComboBox
        self.cbFormats = QComboBox(self)
        self.cbFormats.currentIndexChanged.connect(self.on_cbFormats_changed)
        # read in the option list
        splash.updateProgress("Reading Formats")
        formats = self.readInOptions("formats")
        self.splitFormats(formats, self.cbFormats)
        
        # Create a QComboBox
        self.cbArchitectures = QComboBox(self)
        self.cbArchitectures.currentIndexChanged.connect(self.on_cbPayloads_changed)
        # read in the option list
        splash.updateProgress("Reading Architectures")
        payloads = self.readInOptions("archs")
        self.splitFormats(payloads, self.cbArchitectures)

        self.tbPort = QLineEdit(self)
        self.tbPort.setValidator(QRegExpValidator(QRegExp("[0-9]+")))
        self.tbHost = QLineEdit(self)
        # I think this is an error, we probably want this to be able to be a webaddress too,
        # not just an IP address
        self.tbHost.setValidator(QRegExpValidator(QRegExp("[0-9.]+")))
        self.tbOutfile = QLineEdit(self)
        self.tbVariable = QLineEdit(self)

        self.pbCharacterOptions = QPushButton("BadChars", self)
        self.pbCharacterOptions.clicked.connect(self.onCharacterOptionsClicked)
        self.tbBadChars = QLineEdit(self)
        #self.tbBadChars.setValidator(QRegExpValidator(QRegExp("(\\x[0-9a-f][0-9a-f])*")))

        self.pbSubmit = QPushButton("Generate", self)
        self.pbSubmit.clicked.connect(self.onSubmitClicked)

        # Add the QComboBox to a QVBoxLayout
        layout = QVBoxLayout()
        formlayout = QFormLayout()
        formlayout.addRow("&Payload:", self.cbPayloads)
        formlayout.addRow("&Format:", self.cbFormats)
        formlayout.addRow("&Arch:", self.cbArchitectures)
        formlayout.addRow(self.pbCharacterOptions, self.tbBadChars)
        formlayout.addRow("P&ort:", self.tbPort)
        formlayout.addRow("&Remote Host:", self.tbHost)
        formlayout.addRow("&Outfile:", self.tbOutfile)
        formlayout.addRow("&Variable Name:", self.tbVariable)
        layout.addLayout(formlayout)
        layout.addWidget(self.pbSubmit)
        self.setLayout(layout)

        # now load in our saved settings from before
        splash.updateProgress("Loading Settings")
        self.load_settings()

        # Now that we are all done, tell the splash screen we are done.
        splash.updateProgress("Done")

    def splitPayloads(self, payloads, box):
        # so the msfvenom command returns a list of strings starting on the 6th one. Then from there, each item has a payload and description
        #import pdb; pdb.set_trace()
        for a in payloads[6:].split('\n'):
            left = a.strip().split(' ')[0]
            right = a.strip()[len(left):].strip()
            box.addItem(left, userData=right)
    
    def splitFormats(self, payloads, box):
        # so the msfvenom command returns a list of strings that have two sets of headers. Each header is 6 
        i = 0
        while i < len(payloads.split('\n'))-1:
            if len(payloads.split('\n')[i]) == 0:
                i += 6
                continue
            box.addItem(payloads.split('\n')[i].strip())
            i=i+1

    def load_settings(self):
        saved_index = self.settings.value("cbPayloads_index", type=int)
        if saved_index is not None:
            self.cbPayloads.setCurrentIndex(saved_index)
        saved_index = self.settings.value("cbFormats_index", type=int)
        if saved_index is not None:
            self.cbFormats.setCurrentIndex(saved_index)
        saved_index = self.settings.value("cbArchitectures_index", type=int)
        if saved_index is not None:
            self.cbArchitectures.setCurrentIndex(saved_index)
        saved_index = self.settings.value("tbPort", type=int)
        if saved_index is not None:
            self.tbPort.setText(str(saved_index))
        saved_index = self.settings.value("tbHost", type=int)
        if saved_index is not None:
            self.tbHost.setText(str(saved_index))
        saved_index = self.settings.value("tbOutfile", type=str)
        if saved_index is not None:
            self.tbOutfile.setText(saved_index)
        saved_index = self.settings.value("tbVariable", type=str)
        if saved_index is not None:
            self.tbVariable.setText(saved_index)
    
    def save_settings(self):
        self.settings.setValue("cbPayloads_index", self.cbPayloads.currentIndex())
        self.settings.setValue("cbFormats_index", self.cbFormats.currentIndex())
        self.settings.setValue("cbArchitectures_index", self.cbArchitectures.currentIndex())
        if self.tbPort.text() != "":
            self.settings.setValue("tbPort", self.tbPort.text())
        if self.tbHost.text() != "":
            self.settings.setValue("tbHost", self.tbPort.text())
        if self.tbOutfile.text() != "":
            self.settings.setValue("tbOutfile", self.tbOutfile.text())
        if self.tbVariable.text() != "":
            self.settings.setValue("tbVariable", self.tbVariable.text())

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)

    # if we wanted to have something be different based on a selection, it happens here. Should check the architecture?  
    def on_cbPayloads_changed(self, index):
        return 
        
    # if we wanted to have something be different based on a selection, it happens here. Should check the architecture?
    def on_cbFormats_changed(self, index):
        return

    # Now we are going to build the command based on what is all selected within the boxes
    def onSubmitClicked(self):
        self.pbSubmit.setEnabled(False)
        commandString = "msfvenom"
        commandString = commandString + " -p " + self.cbPayloads.currentText()
        commandString = commandString + " -f " + self.cbFormats.currentText()
        commandString = commandString + " -a " + self.cbArchitectures.currentText()
        if self.tbHost.text() != "":
            commandString = commandString + " LHOST=" + self.tbHost.text()
        if self.tbPort.text() != "":
            commandString = commandString + " LPORT=" + self.tbPort.text()
        if self.tbOutfile.text() != "":
            commandString = commandString + " -o " + self.tbOutfile.text()
        if self.tbVariable.text() != "":
            commandString = commandString + " -v " + self.tbVariable.text()
        if self.tbBadChars.text() != "":
            commandString = commandString + " -b '" + self.tbBadChars.text() + "'"
        if self.executeCmd(commandString, "") is None:
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("An Error Occurred")
            msg_box.setText("That combination is not allowed, relook at your settings!")
            msg_box.exec()
        print(commandString)
        self.pbSubmit.setEnabled(True)
        return
    
    # this really needs to be updated to run as its own thread so it doesn't hold up the rest of the stuff
    def executeCmd(self, cmd, params):
        try:
            output = subprocess.check_output(cmd + " " + params, shell=True)
        except:
            print("Unable to execute msfvenom command, ensure execution is available on the system")
            return None # If we return this, the rest of the program breaks. We need a clean way to warn the user
        return output

    def readInOptions(self, option):
        # Get the command to read in the options based on what we want
        return self.executeCmd('msfvenom -l', option).decode("utf-8")

    def onCharacterOptionsClicked(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Bad Character Options")
        layout = QVBoxLayout()
        dialog.list_view = QListView(self)
        layout.addWidget(dialog.list_view)
        dialog.model = QStandardItemModel(dialog.list_view)
        dialog.list_view.setModel(dialog.model)
        for a in range(0, 256):
            item = QStandardItem("\\x" + format(a, '02x'))
            item.setCheckable(True)
            dialog.model.appendRow(item)
        buttonBox = QDialogButtonBox(QDialogButtonBox.Ok|QDialogButtonBox.Cancel)
        buttonBox.accepted.connect(dialog.accept)
        buttonBox.rejected.connect(dialog.reject)
        layout.addWidget(buttonBox)
        dialog.setLayout(layout)
        if dialog.exec() == QDialog.Accepted:
            result = ""
            for row in range(dialog.model.rowCount()):
                item = dialog.model.item(row)
                if item.checkState() == 2:
                    result = result + item.text()
            self.tbBadChars.setText(result.replace('0x', '\\x'))
        return

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet('''
        #LabelTitle {
            font-size: 60px;
            color: #93deed;
        }

        #LabelDesc {
            font-size: 30px;
            color: #c2ced1;
        }

        #LabelLoading {
            font-size: 30px;
            color: #e8e8eb;
        }

        #kickoff{
            background-color: #2F4454;

        }

        QProgressBar {
            background-color: #DA7B93;
            color: rgb(200, 200, 200);
            border-style: none;
            border-radius: 10px;
            text-align: center;
            font-size: 30px;
        }

        QProgressBar::chunk {
            border-radius: 10px;
            background-color: qlineargradient(spread:pad x1:0 x2:1 y1:0.511364, y2:0.523, stop:0 #1C3B34, stop:1 #376E6F);
        }
    ''')

    splash = SplashScreen()
    splash.show()
    window = MainWindow(splash)
    window.show()
    #splash.close()
    sys.exit(app.exec())
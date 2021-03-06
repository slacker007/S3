#!/usr/bin/python 

import argparse
import sys
import xml.sax
import os.path
import xml.dom.minidom
from getpass import getpass
from neo4jrestclient.client import GraphDatabase
from xml.dom.minidom import parse as p


parser = argparse.ArgumentParser()
parser.add_argument("--input", help='Input file in XML format', type=str, required=True)
args = parser.parse_args()

def getXMLfile():
    if os.path.isfile(args.input):
        print 'Found -> %s' % args.input
        return 0
    else:
        print 'ERROR: Unable to find -> %s' % args.input
        sys.exit()

def create_session():
    '''
    Gets IP of server & returns session token
    '''

    neoip = "0"
    neoip = raw_input('Enter IP of neo4j DB or press [ENTER] for localhost: ')

    if neoip == '':
        print "Using 'localhost' "
        neoip = 'localhost'
    neoun = "0"
    neoun = raw_input('Enter neo4j DB username or press [ENTER] for neo4j: ')

    if len(neoun) == 0:
        neoun = "neo4j"
    addr = 'https://' + neoip + ':7473/db/data/'
    gdb = GraphDatabase(addr, username=neoun, password=getpass('Enter neo4j password: '))
    return gdb

class SecurityEventHandler(xml.sax.ContentHandler):
    evtprops = []
    gdb = create_session()
    def __init__(self):
        self.CurrentData = ""
        self.Provider = ""
        self.EventID = ""
        self.Version = ""
        self.Level = ""
        self.Task = ""
        self.Opcode = ""
        self.Keywords = ""
        self.TimeCreated = ""
        self.EventRecordID = ""
        self.Correlation = ""
        self.Execution = ""
        self.Channel = ""
        self.Computer = ""
        self.Security = ""
        self.UserData = ""
        self.SubjectUserName = ""
        self.SubjectDomainName = ""
        self.SubjectLogonId = ""
        self.Data = ""
        self.Name = ""

    def startElement(self, tag, attributes):
        self.CurrentData = tag
        if tag == "Event":
            for x in self.evtprops:
                pass
            #print x
            #raw_input()
            if len(self.evtprops) > 0:
                secevt = self.gdb.nodes.create()
                for x in self.evtprops:
                    try:
                        secevt[str(x[0])] = str(x[1])
                    except:
                        print ("Exception", x)
                secevt.labels.add("SecurityEvent")
                del self.evtprops[:]
        elif tag == "TimeCreated":
            spl_time = attributes["SystemTime"].split()
            self.evtprops.append(("TIME", spl_time))
        elif tag == "Provider":
            self.evtprops.append(("Name", attributes["Name"]))
            self.evtprops.append(("GUID", attributes["Guid"]))
        elif tag == "Execution":
            self.evtprops.append(("PID", attributes["ProcessID"]))
            self.evtprops.append(("TID", attributes["ThreadID"]))
        elif tag == "Security":
            self.evtprops.append(("UID", attributes["UserID"]))
        elif tag == "Data":
            try:
                self.evtprops.append(attributes["Name"])
                endElement(self, tag)
            except:
                pass
        else:
            pass

    def endElement(self, tag):
        if self.CurrentData == "Computer":
            self.evtprops.append(("CN", self.Computer))
        elif self.CurrentData == "EventID":
            self.evtprops.append(("EID", self.EventID))
        elif self.CurrentData == "Version":
            self.evtprops.append(("Version", self.Version))
        elif self.CurrentData == "Level":
            self.evtprops.append(("Level", self.Level))
        elif self.CurrentData == "Task":
            self.evtprops.append(("Task", self.Task))
        elif self.CurrentData == "Opcode":
            self.evtprops.append(("Opcode", self.Opcode))
        elif self.CurrentData == "Keywords":
            self.evtprops.append(("KW", self.Keywords))
        elif self.CurrentData == "EventRecordID":
            self.evtprops.append(("ERID", self.EventRecordID))
        elif self.CurrentData == "SubjectLogonId":
            self.evtprops.append(("Sub LID", self.SubjectLogonId))
        elif self.CurrentData == "Data":
            temp = self.evtprops[len(self.evtprops) - 1]
            self.evtprops.remove(temp)
            self.evtprops.append((temp, self.Data))
        elif self.CurrentData == "SubjectUserName":
            self.evtprops.append(("SubjectUserName", self.SubjectUserName))
        else:
            pass

    def characters(self, content):
        if self.CurrentData == "Provider":
            self.Provider = content
        elif self.CurrentData == "EventID":
            self.EventID = content
        elif self.CurrentData == "Version":
            self.Version = content
        elif self.CurrentData == "Level":
            self.Level = content
        elif self.CurrentData == "Task":
            self.Task = content
        elif self.CurrentData == "Opcode":
            self.Opcode = content
        elif self.CurrentData == "Keywords":
            self.Keywords = content
        elif self.CurrentData == "EventRecordID":
            self.EventRecordID = content
        elif self.CurrentData == "Computer":
            self.Computer = content
        elif self.CurrentData == "SubjectLogonId":
            self.SubjectLogonId = content
        elif self.CurrentData == "SubjectUserName":
            self.SubjectUserName = content
        elif self.CurrentData == "Data":
            self.Data = content
        elif self.CurrentData == "Name":
            self.Name = content
        else:
            pass

def main():
    '''
    This was written to take in windows security event logs in xml format that has been converted 
    from evtx using [evtxdump.py] from https://github.com/williballenthin/python-evtx (Thanks!)
    Syntax for evtxdump.py is >> python evtxdump.py yourevents.evtx > yourevents.xml
    '''
    getXMLfile()
    parser =xml.sax.make_parser()
    parser.setFeature(xml.sax.handler.feature_namespaces, 0)
    Handler = SecurityEventHandler()
    parser.setContentHandler(Handler)
    parser.parse(args.input)

    return 0

if __name__ == '__main__':
    main()

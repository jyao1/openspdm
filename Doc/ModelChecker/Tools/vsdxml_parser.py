import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict 

print_counter=[0];

messageDict = OrderedDict(
    [
        ('GET_VERSION','VERSION'),
        ('GET_CAPABILITIES','CAPABILITIES'),
        ('NEGOTIATE_ALGORITHMS','ALGORITHMS'),
        ('GET_DIGESTS','DIGESTS'),
        ('GET_CERTIFICATE','CERTIFICATE'),
        ('CHALLENGE','CHALLENGE_AUTH'),
        ('GET_MEASUREMENTS', 'MEASUREMENTS'),
        ('KEY_EXCHANGE','KEY_EXCHANGE_RSP'),
        ('FINISH','FINISH_RSP'),
        ('PSK_EXCHANGE','PSK_EXCHANGE_RSP'),
        ('PSK_FINISH','PSK_FINISH_RSP'),
        ('KEY_UPDATE','KEY_UPDATE_ACK'),
        ('GET_ENCAPSULATED_REQUEST','ENCAPSULATED_REQUEST'),
        ('DELIVER_ENCAPSULATED_RESPONSE','ENCAPSULATED_RESPONSE_ACK'),
        ('HEARTBEAT','HEARTBEAT_ACK'),
        ('END_SESSION','END_SESSION_ACK'),
        ('VENDOR_DEFINED_REQUEST','VENDOR_DEFINED_RESPONSE')
    ]
)

functionDict = OrderedDict(
    [
        ("129", "GET_DIGESTS"),  
        ("130", "GET_CERTIFICATE"),  
        ("131", "CHALLENGE"),  
        ("132", "GET_VERSION"),  
        ("224", "GET_MEASUREMENTS"),  
        ("225", "GET_CAPABILITIES"),  
        ("227", "NEGOTIATE_ALGORITHMS"),  
        ("228", "KEY_EXCHANGE"),  
        ("229", "FINISH"),  
        ("230", "PSK_EXCHANGE"),  
        ("231", "PSK_FINISH"),  
        ("232", "HEARTBEAT"),  
        ("233", "KEY_UPDATE"),  
        ("234", "GET_ENCAPSULATED_REQUEST"),  
        ("235", "DELIVER_ENCAPSULATED_RESPONSE"),  
        ("236", "END_SESSION"),  
        ("255", "RESPOND_IF_READY"),  
        ("254", "VENDOR_DEFINED_REQUEST"),  
        ("1", "DIGESTS"),  
        ("2", "CERTIFICATE"),  
        ("3", "CHALLENGE_AUTH"),  
        ("4", "VERSION"),  
        ("96", "MEASUREMENTS"),  
        ("97", "CAPABILITIES"),  
        ("99", "ALGORITHMS"),  
        ("100", "KEY_EXCHANGE_RSP"),  
        ("101", "FINISH_RSP"),  
        ("102", "PSK_EXCHANGE_RSP"),  
        ("103", "PSK_FINISH_RSP"),  
        ("104", "HEARTBEAT_ACK"),  
        ("105", "KEY_UPDATE_ACK"),  
        ("106", "ENCAPSULATED_REQUEST"),  
        ("107", "ENCAPSULATED_RESPONSE_ACK"),  
        ("108", "END_SESSION_ACK"),  
        ("126", "VENDOR_DEFINED_RESPONSE"),  
        ("127", "ERROR"),  
    ]
)

class AcesDiagram:
    """
    """
    def __init__(self, fileName):
        self._root = ET.parse(fileName).getroot()
        rtag = self._root.tag
        if (rtag.find('}') >= 0):
            ns, _ = rtag.split('}', 1)
            self._NS = ns+'}'       # because rtag.split removes the }
        else:
            self._NS = ''

        data  = self._root.find(self._NS + 'Data')
        self._diagrams = data.findall(self._NS + 'Diagram')

    def extract(self, diagram):
        name  = diagram.find(self._NS + 'Name').text
        nodes = diagram.findall(self._NS + 'Node')
        edges = diagram.findall(self._NS + 'Edge')
        id2text = {} # {'424': 'L1', '420': 'L2', '416': 'L3'}
        for ne in nodes+edges:
            Text = ne.find(self._NS + 'Text').text
            if Text is None:
                props = ne.findall(self._NS + 'CustomProperty')
                for p in props:
                    if p.attrib['Name']=='InstanceName':
                        Text = p.attrib['Value']
                        break
            id2text[ne.attrib['Id']] = Text


        def proc_node_edge(ne):
#             Name = ne.find(self._NS + 'Name').text
            Type = ne.find(self._NS + 'Type').text
            Text = ne.find(self._NS + 'Text').text
#             id2text[ne.attrib['Id']] = Text
            props = ne.findall(self._NS + 'CustomProperty')
            d = {}
            ignore_props = ["DisplayLength", "DisplayWidth", "StencilName", "StencilVersion"]
            for p in props:
                nm = p.attrib['Name']
                if nm not in ignore_props:
                    d[nm] = p.attrib['Value']
            subnodes = ne.findall(self._NS + 'Subnode')
            return {'Id': ne.attrib['Id'], 'Type':  Type, 'Text':  Text, 'Subs': subnodes, 'Props': d}

        ns = [proc_node_edge(n) for n in nodes]
        es = [proc_node_edge(e) for e in edges]
        return (name, ns, es) # Nodes, Edges

    def diagram_iter(self):
        for d in self._diagrams:
            name, ns, es = self.extract(d)
#             pprint.pprint(ns)
#             pprint.pprint(es)
            yield (name, ns, es)

def findNode(nodeId, nodes):
    for node in nodes:
        # print (node['Id'], nodeId)
        if node['Id']==nodeId:
            return node

def findEdgeByText(edgeText, edges):
    for edge in edges:
        # print (edge['Id'], edgeText)
        if edge['Text']==edgeText:
            return edge

def findEdge(edgeId, edges):
    for edge in edges:
        # print (edge['Id'], edgeId)
        if edge['Id']==edgeId:
            return edge

def findSourceNodeByEdges(nodeId, edges):
    for edge in edges:
        for sub_node in edge['Subs']:
            # print(sub_node.get('IsSource'), sub_node.get('Id'), nodeId, sub_node.get('Id')==nodeId)
            if sub_node.get('IsSource')=='true' and sub_node.get('Id')==nodeId:
                #print(edge['Text'])
                return edge #findNode(nextN, nodes)

def findToNodeForEdge(edge, nodes):
    for sub_node in edge['Subs']:
        if sub_node.get('IsSource')=='false':
            nextN=sub_node.get('Id')
            return findNode(nextN, nodes)


def addHeader(f, file):
    f_header=open(file,"r")
    lines=f_header.readlines()
    f.writelines(lines)
    f.write("\n\n\n")
    f_header.close()

def addInit(f, agents, nodes):
    f.write("init{\n")
    f.write("    atomic{\n")
    for node in agents:
        if "Respon" in node['Props']['BpmnName'] and "VEN" not in node['Props']['BpmnName']:
            print (node)
            for sub in node['Subs']:
                sub_id = sub.get('Id')
                sub_node = findNode(sub_id, nodes)
                if sub_node!=None:
                    node_text = findNode(sub_id, nodes)['Text'].split("_2")[0]
                    f.write("        Requester_Cache."+node_text.lower()+"=3;\n")
                    f.write("        Responder_Cache."+node_text.lower()+"=3;\n")
    f.write("    }\n")
    f.write("\n")
    f.write("    atomic{\n")
    for node in agents:
        if "VEN" not in node['Props']['BpmnName']:
            f.write("        run "+node['Props']['BpmnName']+"(spdm1Que, spdm1Spd);\n")
    # f.write("        run Responder(spdm1Que, spdm1Spd);\n")
    f.write("    }\n")
    f.write("}\n")

def addProperties(f):
    property_counter=0
    # GET_VERSION 1
    f.write("// GET_VERSION 1\n")
    for key,value in messageDict.items():
        if key!="GET_VERSION":
            f.write("ltl p"+str(property_counter)+" {!<> ((version_match == 0) && (signal=="+value+"))};\n")
            property_counter+=1
            f.write("ltl p"+str(property_counter)+" {!<> ((version_match == 0) && (response_signal=="+key+"))};\n")
            property_counter+=1

    # GET_VERSION 2
    # GET_CAPABILITIES 1
    # NEGOTIATE_ALGORITHMS 3
    f.write("// GET_VERSION 2, GET_CAPABILITIES 1, NEGOTIATE_ALGORITHMS 3\n")
    f.write("ltl p"+str(property_counter)+" {!<> (signal==ERROR && param1 == ResponseNotReady && version_match!=1)}; \n");
    property_counter+=1
    f.write("ltl p"+str(property_counter)+" {!<> (signal==ERROR && param1 == ResponseNotReady && capabilities_match!=1)}; \n");
    property_counter+=1
    f.write("ltl p"+str(property_counter)+" {!<> (signal==ERROR && param1 == ResponseNotReady && algorithms_match!=1)}; \n");
    property_counter+=1

    # NEGOTIATE_ALGORITHMS 1
    f.write("// NEGOTIATE_ALGORITHMS 1\n")
    f.write("ltl p"+str(property_counter)+" {!<> ((capabilities_match == 0) && (response_signal==NEGOTIATE_ALGORITHMS))};\n")
    property_counter+=1

    # NEGOTIATE_ALGORITHMS 2
    f.write("// NEGOTIATE_ALGORITHMS 2\n")
    f.write("ltl p"+str(property_counter)+" {!<> ((algorithms_match == 0 && capabilities_match == 1) && (response_signal==GET_CAPABILITIES))};\n")
    property_counter+=1
    for key,value in messageDict.items():
        if key!="GET_VERSION" and key!="GET_CAPABILITIES" and key!="NEGOTIATE_ALGORITHMS":
            f.write("ltl p"+str(property_counter)+" {!<> ((algorithms_match == 0) && (signal=="+value+"))};\n")
            property_counter+=1
            f.write("ltl p"+str(property_counter)+" {!<> ((algorithms_match == 0) && (response_signal=="+key+"))};\n")
            property_counter+=1

    # CHALLENGE 1 (partially)
    f.write("// CHALLENGE 1\n")
    f.write("ltl p"+str(property_counter)+"{(<> (signal==VERSION W signal==PSK_EXCHANGE_RSP)) || (<> (signal==VERSION W signal==CAPABILITIES)) || (<> (signal==VERSION W signal==ERROR))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1 #(above succeed)
    f.write("ltl p"+str(property_counter)+"{(<> (signal==CAPABILITIES W signal==ALGORITHMS)) || (<> (signal==CAPABILITIES W signal==ERROR))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1 #(above succeed)
    ## f.write("ltl p"+str(property_counter)+"{(<> (signal==VERSION W signal==CAPABILITIES W signal==ALGORITHMS W signal==DIGESTS)) };\n")# W signal==PSK_EXCHANGE_RSP W signal==PSK_EXCHANGE_RSP)) };\n")# W signal==ALGORITHMS)};\n")
    ## f.write("ltl p"+str(property_counter)+"{(<> (signal==VERSION W signal==CAPABILITIES W signal==ALGORITHMS)) };\n")# W signal==PSK_EXCHANGE_RSP W signal==PSK_EXCHANGE_RSP)) };\n")# W signal==ALGORITHMS)};\n")
    # f.write("ltl p"+str(property_counter)+"{(<> (signal==ALGORITHMS W signal==PSK_EXCHANGE_RSP)) || (<> (signal==ALGORITHMS W signal==VENDOR_DEFINED_RESPONSE)) || (<> (signal==ALGORITHMS W signal==DIGESTS)) || (<> (signal==ALGORITHMS W signal==ERROR))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1 #(above succeed)
    # f.write("ltl p"+str(property_counter)+"{(<> (signal==PSK_EXCHANGE_RSP W signal==VENDOR_DEFINED_RESPONSE)) || (<> (signal==DIGESTS W signal==CERTIFICATE)) || (<> (signal==DIGESTS W signal==ERROR))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1
    # f.write("ltl p"+str(property_counter)+"{(<> (signal==CERTIFICATE W signal==KEY_EXCHANGE_RSP)) || (<> (signal==CERTIFICATE W signal==CHALLENGE)) || (<> (signal==CERTIFICATE W signal==ERROR))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1

    # GET_MEASUREMENTS 1
    f.write("// GET_MEASUREMENTS 1\n")
    f.write("ltl p"+str(property_counter)+"{!<> (response_signal==GET_MEASUREMENTS && (!(MEAS_CAP==1 || MEAS_CAP==2)))}; \n")# W signal==ALGORITHMS)};\n")
    property_counter+=1
    # GET_MEASUREMENTS 2
    f.write("// GET_MEASUREMENTS 2\n")
    # f.write("ltl p"+str(property_counter)+"{!<> (MEAS_FRESH_CAP==0 && (measurements_match==1||Requester_Cache.measurements_match==1) && response_signal==GET_MEASUREMENTS)}; \n")# W signal==ALGORITHMS)};\n")
    property_counter+=1 #(above fails because currently cannot have gloabl property for this, switch to local assertions)
    # GET_MEASUREMENTS 3
    f.write("// GET_MEASUREMENTS 3\n")
    f.write("ltl p"+str(property_counter)+"{!<> ((challenge_auth_match == 0) && (response_signal==GET_MEASUREMENTS))}; \n")
    property_counter+=1

    # ERROR 1
    f.write("// ERROR 1\n")
    # f.write("ltl p"+str(property_counter)+"{!<> ((global_error == 1) && (signal!=ERROR))}; \n")
    property_counter+=1 # (above turn to assertions)

    # VENDOR_DEFINED_REQUEST 1
    f.write("// VENDOR_DEFINED_REQUEST 1\n")
    f.write("ltl p"+str(property_counter)+"{!<> ((version_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; \n")
    property_counter+=1 
    f.write("ltl p"+str(property_counter)+"{!<> ((capabilities_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; \n")
    property_counter+=1 
    f.write("ltl p"+str(property_counter)+"{!<> ((algorithms_match == 0) && (response_signal==VENDOR_DEFINED_REQUEST))}; \n")
    property_counter+=1 

    # FINISH 1
    f.write("// FINISH 1\n")
    # f.write("ltl p"+str(property_counter)+"{(<> (signal==KEY_EXCHANGE W signal==ERROR)) || (<> (signal==KEY_EXCHANGE W signal==FINISH))};\n")# W signal==ALGORITHMS)};\n")
    # f.write("ltl p"+str(property_counter)+"{(<> (signal==KEY_EXCHANGE W signal==ERROR) || (signal==KEY_EXCHANGE W signal==FINISH))};\n")# W signal==ALGORITHMS)};\n")
    property_counter+=1 #(above fails for multiple cases, and turns out to be okay to not have properties for this)

    # PSK_EXCHAGE 7
    f.write("// PSK_EXCHAGE 7\n")
    f.write("ltl p"+str(property_counter)+"{!<> ((version_match == 0) && (response_signal==PSK_EXCHANGE))}; \n")
    property_counter+=1
    # PSK_EXCHAGE 11
    f.write("// PSK_EXCHAGE 11\n")
    # f.write("ltl p"+str(property_counter)+"{<> ((PSK_CAP==2) && (response_signal==PSK_EXCHANGE))}; \n")
    property_counter+=1 #(add to assertions)


def printErrorRelated(link_prev_list, key, response_code, f, space, special_character):
    for link_prev in link_prev_list:
        f.write(""+space+"    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code=="+messageDict[link_prev]+"->\n")
        f.write(""+space+"        atomic{\n")
        f.write(""+space+"        printf(\"Has not ResponseNotReady error in "+messageDict[link_prev]+" " + str(print_counter[0]) +"\\n\");\n")
        print_counter[0]+=1
        f.write("                 // KEY_UPDATE 6\n")
        f.write("                 assert(ERROR_response_code=="+messageDict[link_prev]+");\n")
        f.write(""+space+"        Que!channelType(0, 0, 0, "+link_prev+", 0);\n")
        f.write(""+space+"        goto "+response_code+"_1"+special_character+";\n")
        f.write(""+space+"        }\n")
        if "VERSION" not in link_prev and "CAPABILITIES" not in link_prev and "ALGORITHMS" not in link_prev:
            f.write(""+space+"    :: signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code=="+messageDict[link_prev]+" ->\n")
            f.write(""+space+"        atomic{\n")
            f.write(""+space+"        printf(\"ResponseNotReady error in "+messageDict[link_prev]+" " + str(print_counter[0]) +"\\n\");\n")
            print_counter[0]+=1
            # f.write(""+space+"        RESPOND_IF_READY_response_code="+link_prev+";\n")
            f.write(""+space+"        goto RespondIfReady_1;\n")
            f.write(""+space+"        }\n")
        if "HEARTBEAT" in link_prev:
            f.write(""+space+"    :: signal==ERROR && param1==InvalidSessionID && ERROR_response_code=="+messageDict[link_prev]+"->\n")
            f.write(""+space+"        atomic{\n")
            f.write(""+space+"        printf(\"Has InvalidSessionID error in "+messageDict[link_prev]+" " + str(print_counter[0]) +"\\n\");\n")
            print_counter[0]+=1
            f.write("        // HEARTBEAT 4\n")
            f.write("        assert(param1!=InvalidSessionID||(param1==InvalidSessionID && "+link_prev+"==HEARTBEAT));\n")
            f.write(""+space+"        Que!channelType(0, 0, 0, END_SESSION, 0);\n")
            f.write(""+space+"        if  \n")
            # f.write(""+space+"         :: skip -> goto GET_VERSION_1; \n")
            f.write(""+space+"         :: skip -> goto KEY_EXCHANGE_1; \n")
            f.write(""+space+"         :: skip -> goto PSK_EXCHANGE_1; \n")
            f.write(""+space+"        fi \n")
            # f.write(""+space+"        goto "+response_code+"_1"+special_character+";\n")
            f.write(""+space+"        }\n")
        f.write(""+space+"    :: signal=="+messageDict[link_prev]+" && signal2!=Requester_Cache."+messageDict[link_prev].lower()+" ->\n")
        f.write(""+space+"        atomic{\n")
        f.write(""+space+"        printf(\""+messageDict[link_prev].lower()+" " + str(print_counter[0]) +" not match\\n\");\n")
        print_counter[0]+=1
        f.write(""+space+"        "+messageDict[link_prev].lower()+"_match=2;\n")
        f.write("                 // KEY_UPDATE 6\n")
        f.write("                 assert(ERROR_response_code=="+messageDict[link_prev]+");\n")
        f.write(""+space+"        Que!channelType(0, 0, 0, "+link_prev+", 0);\n")
        f.write(""+space+"        goto "+response_code+"_1"+special_character+";\n")
        f.write(""+space+"        }\n")


def node2Measurements(f, node, edges, nodes):
    if node['Type']=='Branch':
        print("node: ", node['Props']['Case'])
        from_list=node['Props']['Case'].split('], [')[0][2:]
        to_list=node['Props']['Case'].split('], [')[1][:-2].split(', ')
        # f.write("GET_MEASUREMENTS_1:\n")
        f.write("    Spd?channelType(0,0,param1,signal,signal2);\n")
        f.write("    if \n")
        f.write("    :: signal==CHALLENGE_AUTH && signal2==Requester_Cache.challenge_auth ->\n")
        f.write("        atomic{\n")
        f.write("        printf(\"\t\t\t\t\t\t\tchallenge_auth match\\n\");\n")
        f.write("        Requester_Cache.challenge_auth_match=1;\n")
        f.write("        challenge_auth_match=1;\n")
        f.write("        if\n")
        for to_edge in to_list:
            edge=findEdgeByText(to_edge, edges)
            if edge!=None:
                to_node=findToNodeForEdge(edge, nodes)['Text']
                f.write("        :: "+edge['Text']+"->\n")
                if '!' not in edge['Text']:
                    f.write("            support_measurements=1;\n")
                f.write("            goto "+to_node+";\n")
        f.write("        fi\n")
        f.write("        //Que!channelType(0, 0, 0, CHALLENGE, 0);\n")
        f.write("        //goto GET_MEASUREMENTS_1;\n")
        f.write("        }  \n")
        response_code=node['Text'].split('_1')[0]
        link_prev, link_next, key = messageDict._OrderedDict__map[response_code]
        printErrorRelated([link_prev[2]], key, response_code, f,"","")
        f.write("    :: else ->\n")
        f.write("        atomic{\n")
        f.write("        printf(\""+key+" has error\\n\");\n") #messageDict[link_prev[2]].lower()
        f.write("        }\n")
        f.write("    fi\n")
    elif node['Type']=='Task':
        node_id = node.get('Id')
        edge=findSourceNodeByEdges(node_id, edges)
        if edge==None:
            f.write("    if \n")
            f.write("    :: support_measurements==1 ->{\n")
            f.write("        Spd?channelType(0,0,param1,signal,signal2);\n")
            f.write("        if \n")
            f.write("        :: signal==MEASUREMENTS && signal2==Requester_Cache.measurements ->\n")
            f.write("           atomic{\n")
            f.write("           printf(\"\t\t\t\t\t\t\tmeasurements match\\n\");\n")
            f.write("           Requester_Cache.measurements_match=1;\n")
            f.write("           measurements_match=1;\n")
            f.write("           printf(\"Keep requesting GET_MEASUREMENTS or GET_VERSION\\n\");\n")
            f.write("           if  \n")
            f.write("           :: skip -> atomic{//Que!channelType(0, 0, 0, GET_MEASUREMENTS, 0); \n")
            f.write("                             goto GET_MEASUREMENTS_12;} \n")# +node['Props']['Action']+";\n")
            f.write("           :: skip -> atomic{goto GET_VERSION_1;} \n")
            f.write("           fi \n")
            f.write("           } \n")
            response_code=node['Text'].split('_1')[0]
            link_prev, link_next, key = messageDict._OrderedDict__map[response_code]
            printErrorRelated([key], key, response_code, f,"\t","1")
            f.write("        fi} \n")
            f.write("    :: else ->\n")
            f.write("        printf(\"Measurement is not supported. \\n\");\n")  
            f.write("        goto LEAVE;\n")
            f.write("    fi \n")
            
        else:
            if "MEASUREMENTS" in edge['Text']:
                f.write("    if \n")
                f.write("    :: MEAS_FRESH_CAP==0 ->\n")
                f.write("        atomic{\n")
                f.write("        Requester_Cache.measurements_match=0;\n")
                f.write("        measurements_match=0;\n")
                f.write("        printf(\"Send reset before GET_MEASUREMENTS\\n\");\n")
                f.write("        }\n")
                f.write("    fi \n")
                f.write("        // GET_MEASUREMENTS 2\n")
                f.write("        assert(!(MEAS_FRESH_CAP==0 && measurements_match==1));\n")#!(MEAS_FRESH_CAP==0 && (measurements_match==1||Requester_Cache.measurements_match=1)));\n")
                f.write("        atomic{\n")
                send_message=list(messageDict.keys())[list(messageDict.values()).index(findToNodeForEdge(edge,nodes)['Text'].split('_2')[0])]
                f.write("        Que!channelType(0, 0, 0, "+send_message+", 0);\n")
                f.write("        goto "+node['Props']['Action']+";\n")
                f.write("        }\n")

def agent2Proctype (strr, f, subs, nodes, edges):
    f.write("proctype "+strr+"(chan Que, Spd)\n")
    f.write("{\n")
    # start state of requester
    if "Reque" in strr and "VEN" not in strr:
        f.write("INI:\n")
        f.write("    goto GET_VERSION_1;\n")
    elif "Respon" in strr and "VEN" not in strr:
        f.write("START:   \n")
        f.write("    if\n")
        f.write("    :: 1==0 ->\n")
        f.write("        { printf(\"to nego in responder\\n\"); /*goto NEGOTIATE_ALGORITHMS_2;*/}\n")
        f.write("    :: else ->\n")
        f.write("    atomic{\n")
        f.write("        printf(\"to wait for reque\\n\");// goto START;}\n")
        f.write("        Que?channelType(0, 0, response_param1, response_signal, 0);\n")
        f.write("        if \n")
        f.write("        :: skip->global_error=0;\n")
        f.write("        :: skip->global_error=1;\n")
        f.write("        fi\n")
        f.write("        printf(\"Enter Responder\\n\");\n")
        f.write("        if \n")
        for sub in subs:
            sub_id = sub.get('Id')
            sub_node = findNode(sub_id, nodes)
            if sub_node!=None:
                node_text = findNode(sub_id, nodes)['Text']
                response_code=node_text.split('_2')[0]
                request_code=list(messageDict.keys())[list(messageDict.values()).index(response_code)]
                f.write("        :: response_signal=="+request_code+" -> { printf(\"to get "+response_code.lower()+"\\n\"); printf(\"1 response_signal=%d, global_error=%d\\n\",response_signal, global_error);goto "+response_code+"_2};\n") 
                f.write("        :: response_signal==RESPOND_IF_READY && response_param1=="+request_code+" -> { printf(\"to get "+response_code.lower()+" after error\\n\"); printf(\"2 response_signal=%d, global_error=%d\\n\",response_signal, global_error); goto "+response_code+"_2};\n")        
        # f.write("        :: response_toEncapRsp==1 -> { printf(\"to get encap\\n\"); printf(\"1 response_signal=%d, global_error=%d\\n\",response_signal, global_error);goto ENCAPSULATED_RESPONSE_ACK_2; response_toEncapRsp=0;};\n")
        f.write("        :: else -> { printf(\"will go to somewhere else\\n\"); }\n")
        f.write("        fi\n")
        f.write("    }\n")
        f.write("    fi\n")

    # subnodes of requester and responder
    for i in range( len(subs) - 1, -1, -1) :
        sub=subs[i]
        sub_id = sub.get('Id')
        sub_node = findNode(sub_id, nodes)
        if sub_node!=None and findNode(sub_id, nodes)['Text']!="END_SESSION_11" and findNode(sub_id, nodes)['Text']!="DELIVER_ENCAPSULATED_RESPONSE_11"\
            and findNode(sub_id, nodes)['Text']!="HEARTBEAT_11" and findNode(sub_id, nodes)['Text']!="PSK_FINISH_12"\
            and findNode(sub_id, nodes)['Text']!="FINISH_11" and findNode(sub_id, nodes)['Text']!="VENDOR_DEFINED_REQUEST_11":
            node_text = findNode(sub_id, nodes)['Text']
            f.write(node_text+":\n")
            # print signal
            # f.write("   printf(\"signal=%s\\n\",functionDict[str(signal)]);\n")
            
            # main requester states
            if "Reque" in strr :#and "VEN" not in strr:# and "Respond" not in node_text:
                # f.write("   printf(\"signal=%d, global_error=%d, param1=%d\\n\",signal, global_error, param1);\n")
                
                if "VERSION" in node_text:
                    f.write("atomic{\n")
                    f.write("    Que!channelType(0, 0, 0, GET_VERSION, 0);\n")
                    f.write("   printf(\"signal=%d, global_error=%d, param1=%d\\n\",signal, global_error, param1);\n")
                    # f.write("    if \n")
                    # f.write("    :: skip -> goto GET_CAPABILITIES_1;\n")
                    # f.write("    :: skip -> goto PSK_EXCHANGE_1;\n")
                    # f.write("    fi \n")
                    f.write("    goto GET_CAPABILITIES_1;\n")
                    f.write("}\n")
                elif "RespondIfReady" in node_text:
                    f.write("    if \n")
                    for j in range( len(subs) - 1, -1, -1) :
                        sub_ready=subs[j]
                        sub_ready_id = sub_ready.get('Id')
                        node_ready_text = findNode(sub_ready_id, nodes)
                        if node_ready_text!=None and "RespondIfReady" not in node_ready_text['Text'] \
                            and "VERSION" not in node_ready_text['Text'] \
                            and "CAPABILITIES" not in node_ready_text['Text'] \
                            and "ALGORITHMS" not in node_ready_text['Text'] \
                            and node_ready_text['Text'].split("_1")[1]=='':
                            # and "END_" not in node_ready_text['Text'] 
                            node_ready_text=node_ready_text['Text'].split("_1")[0]
                            link_prev, link_next, key = messageDict._OrderedDict__map[node_ready_text]
                            # set the next state of the current state
                            print(link_prev[2],link_next[2],key)
                            next_num_list=[link_next[2]]
                            if "ALGORITHM" in node_ready_text:
                                next_num_list=[link_next[2], "VENDOR_DEFINED_REQUEST", "PSK_EXCHANGE"]
                            elif "CERTIFICATE" in node_ready_text:
                                next_num_list=[link_next[2], "KEY_EXCHANGE"]
                            elif "FINISH" in node_ready_text or "HEARTBEAT" in node_ready_text \
                                or node_ready_text=="VENDOR_DEFINED_REQUEST" or "KEY_UPDATE" in node_ready_text \
                                or "DELIVER_ENCAPSULATED_RESPONSE" in node_ready_text or "PSK_EXCHANGE" in node_ready_text:
                                next_num_list=["VENDOR_DEFINED_REQUEST",\
                                    "PSK_EXCHANGE", "KEY_EXCHANGE", "KEY_UPDATE", "HEARTBEAT", \
                                    "GET_ENCAPSULATED_REQUEST"]
                                # if "DELIVER_ENCAPSULATED_RESPONSE" in node_ready_text:
                                #     next_num_list.append("DELIVER_ENCAPSULATED_RESPONSE")
                            elif "END_SESSION" in node_ready_text:
                                next_num_list=['KEY_EXCHANGE','PSK_EXCHANGE'] #'GET_VERSION',
                            f.write("    :: param1==ResponseNotReady && RESPOND_IF_READY_response_code=="+messageDict[node_ready_text]+" ->\n")
                            f.write("        atomic{\n")
                            f.write("            // respondIfReady 1\n")
                            f.write("            assert(RESPOND_IF_READY_response_code=="+messageDict[node_ready_text]+");\n")
                            f.write("            Que!channelType(0, 0, "+node_ready_text+", RESPOND_IF_READY, 0);\n")
                            f.write("            printf(\"send RESPOND_IF_READY for "+node_ready_text+"\\n\");\n")
                            if "MEASUREMENTS" in node_ready_text:
                                f.write("            goto "+key+"_11;\n")
                            # elif "VENDOR" in node_ready_text:
                            #     f.write("            goto "+key+"_11;\n")
                            else:
                                # f.write("            goto "+link_next[2]+"_1;\n")
                                f.write("        if \n")
                                if "PSK_EXCHANGE" in node_ready_text:
                                    f.write("        :: PSK_CAP==2 -> goto PSK_FINISH_1;\n")
                                    for next_num in next_num_list:  
                                        f.write("        :: PSK_CAP!=2 -> goto "+next_num+"_1;\n")
                                else:
                                    for next_num in next_num_list:
                                        f.write("        :: skip -> goto "+next_num+"_1;\n")
                                f.write("        fi \n")
                                
                            f.write("        }\n")
                    f.write("    :: else->\n")
                    f.write("        atomic{\n")
                    f.write("        printf(\"respondIfReady parameter error, param1=%d, RESPOND_IF_READY_response_code=%d\\n\", param1, RESPOND_IF_READY_response_code);\n")
                    f.write("        /*goto;*/\n")
                    f.write("        }\n")
                    f.write("    fi\n")
                elif "MEASUREMENT" in node_text:
                    node2Measurements(f, findNode(sub_id, nodes), edges, nodes)
                else:
                    response_code=node_text.split('_1')[0]
                    f.write("    Spd?channelType(0,0,param1,signal,signal2);\n")
                    f.write("    printf(\"signal=%d, global_error=%d, param1=%d\\n\",signal, global_error, param1);\n")
                    # GET_VERSION p2, GET_CAPABILITIES p1
                    if "VERSION" in node_text or "CAPABILITIES" in node_text or "ALGORITHMS" in node_text:
                        f.write("    assert(!(signal==ERROR && param1==ResponseNotReady && RESPOND_IF_READY_response_code=="+messageDict[response_code]+" ))\n")
                    f.write("    if \n")
                    link_prev, link_next, key = messageDict._OrderedDict__map[response_code]
                    # set the previous state of the current state
                    index_num_list=[link_prev[2]]
                    if "11" in node_text:
                        index_num_list=[node_text[:-3]]
                    # elif node_text=="DELIVER_ENCAPSULATED_RESPONSE_1":
                    #     index_num_list=[link_prev[2], "DELIVER_ENCAPSULATED_RESPONSE"]
                    elif node_text=="GET_CAPABILITIES_1":
                        index_num_list=[link_prev[2], "PSK_EXCHANGE", "PSK_FINISH"]
                    elif node_text=="VENDOR_DEFINED_REQUEST_1" or node_text=="PSK_EXCHANGE_1":
                        index_num_list=["NEGOTIATE_ALGORITHMS", "VENDOR_DEFINED_REQUEST",\
                            "PSK_FINISH", "FINISH", "KEY_UPDATE", "HEARTBEAT", \
                            "DELIVER_ENCAPSULATED_RESPONSE", \
                            "PSK_EXCHANGE"]
                        if node_text=="PSK_EXCHANGE_1":
                            index_num_list.append("GET_CAPABILITIES")
                    elif node_text=="KEY_EXCHANGE_1":
                        index_num_list=["GET_CERTIFICATE", "VENDOR_DEFINED_REQUEST",\
                            "PSK_FINISH", "FINISH", "KEY_UPDATE", "HEARTBEAT", \
                            "DELIVER_ENCAPSULATED_RESPONSE", \
                            "PSK_EXCHANGE"]
                    elif node_text=="KEY_UPDATE_1" or node_text=="HEARTBEAT_1" \
                        or node_text=="GET_ENCAPSULATED_REQUEST_1" or node_text=="END_SESSION_1":
                        index_num_list=["VENDOR_DEFINED_REQUEST",\
                            "PSK_FINISH", "FINISH", "KEY_UPDATE", "HEARTBEAT", \
                            "DELIVER_ENCAPSULATED_RESPONSE", \
                            "PSK_EXCHANGE"]

                    for index_num in index_num_list:
                        if index_num=="PSK_EXCHANGE" and response_code!="PSK_FINISH":
                            f.write("    :: signal=="+messageDict[index_num]+" && signal2==Requester_Cache."+messageDict[index_num].lower()+" && PSK_CAP!=2 ->\n")
                        elif (index_num=="PSK_EXCHANGE" and response_code=="PSK_FINISH") or index_num=="PSK_FINISH":
                            f.write("    :: signal=="+messageDict[index_num]+" && signal2==Requester_Cache."+messageDict[index_num].lower()+" && PSK_CAP==2 ->\n")
                        else:
                            f.write("    :: signal=="+messageDict[index_num]+" && signal2==Requester_Cache."+messageDict[index_num].lower()+" ->\n")
                        f.write("        atomic{\n")
                        f.write("        printf(\"\t\t\t\t\t\t\t"+messageDict[index_num].lower()+" " + str(print_counter[0]) +" match\\n\");\n")
                        print_counter[0]+=1
                        f.write("        Requester_Cache."+messageDict[index_num].lower()+"_match=1;\n")
                        f.write("        "+messageDict[index_num].lower()+"_match=1;\n")
                        if messageDict[index_num]=="PSK_EXCHANGE_RSP":
                            f.write("        // PSK_EXCHANGE 11\n")
                            f.write("        assert(PSK_CAP==2 && "+response_code+"==PSK_FINISH||PSK_CAP!=2)\n")
                        if False: #"KEY_UPDATE" in node_text:
                            f.write("        if\n")
                            f.write("        :: "+messageDict[index_num]+"==KEY_UPDATE_ACK && (param1==UpdateKey||param1==UpdateAllKeys)->\n")
                            f.write("        Que!channelType(0, 0, VerifyNewKey, "+response_code+", 0);\n")
                            f.write("        :: else:\n")
                            f.write("        Que!channelType(0, 0, UpdateKey, "+response_code+", 0);\n")
                            f.write("        fi\n")

                        else:
                            f.write("        Que!channelType(0, 0, 0, "+response_code+", 0);\n")
                        # set the next state of the current state
                        next_num_list=[link_next[2]]
                        if "CAPABILITIES" in node_text:
                            next_num_list=[link_next[2], "PSK_EXCHANGE"]
                        elif "ALGORITHM" in node_text:
                            next_num_list=[link_next[2], "VENDOR_DEFINED_REQUEST", "PSK_EXCHANGE"]
                        elif "CERTIFICATE" in node_text:
                            next_num_list=[link_next[2], "KEY_EXCHANGE"]
                        elif "FINISH" in node_text or "HEARTBEAT" in node_text \
                            or node_text=="VENDOR_DEFINED_REQUEST_1" or "KEY_UPDATE" in node_text \
                            or "DELIVER_ENCAPSULATED_RESPONSE" in node_text or "PSK_EXCHANGE" in node_text:
                            next_num_list=["VENDOR_DEFINED_REQUEST",\
                                "PSK_EXCHANGE", "KEY_EXCHANGE", "KEY_UPDATE", "HEARTBEAT", \
                                "GET_ENCAPSULATED_REQUEST"]
                            if node_text=="PSK_EXCHANGE_1":
                                next_num_list.append("GET_CAPABILITIES")
                            # if "DELIVER_ENCAPSULATED_RESPONSE" in node_text:
                            #     next_num_list.append("DELIVER_ENCAPSULATED_RESPONSE")
                        elif "END_SESSION" in node_text:
                            next_num_list=['GET_VERSION','KEY_EXCHANGE','PSK_EXCHANGE']
                        f.write("        if \n")
                        if node_text=="PSK_EXCHANGE_1":
                            f.write("        :: PSK_CAP==2 -> goto PSK_FINISH_1;\n")
                            for next_num in next_num_list:  
                                f.write("        :: PSK_CAP!=2 -> goto "+next_num+"_1;\n")
                        else:
                            for next_num in next_num_list:
                                f.write("        :: skip -> goto "+next_num+"_1;\n")
                        f.write("        fi \n")

                        f.write("        } \n")
                    # to check NEGOTIATE_ALGORITHM 2
                    if "DIGESTS" in node_text:
                        tmp=1
                        f.write("    :: signal==ERROR && param1!=ResponseNotReady && ERROR_response_code==ALGORITHMS->\n")
                        f.write("        atomic{\n")
                        f.write("        printf(\"Has not ResponseNotReady error in NEGOTIATE_ALGORITHMS and will go to GET_VERSION again\\n\");\n")
                        f.write("        Que!channelType(0, 0, 0, GET_VERSION, 0);\n")
                        f.write("        goto GET_CAPABILITIES_1;\n")
                        f.write("        }\n")


                    if "11" in node_text:
                        printErrorRelated(index_num_list, key, response_code, f, "","1")
                    else:
                        printErrorRelated(index_num_list, key, response_code, f, "","")

                    f.write("    :: else ->\n")
                    f.write("        atomic{\n")
                    f.write("        printf(\""+key+" has error, signal=%d, param1=%d, ERROR_response_code=%d, RESPOND_IF_READY_response_code=%d\\n\", signal, param1, ERROR_response_code, RESPOND_IF_READY_response_code);\n") #messageDict[link_prev[2]].lower()
                    f.write("        }\n")
                    f.write("    fi\n")
            # main responder states
            elif "Respon" in strr :#and "VEN" not in strr:# and "Reque" not in node_text:
                f.write("   printf(\"response_signal=%d, global_error=%d, param1=%d\\n\",response_signal, global_error,param1);\n")
                response_code=node_text.split('_2')[0]
                # if "ENCAPSULATED_REQUEST" in response_code:
                #     f.write("   response_toEncapRsp=1;\n")
                if "VEN" in strr:
                    f.write("    Spd?channelType(0,0,response_param1,response_signal,response_signal2);\n")
                f.write("    atomic{\n")
                f.write("        if\n")
                f.write("        :: (response_signal=="+list(messageDict.keys())[list(messageDict.values()).index(response_code)]+" || (response_signal==RESPOND_IF_READY && response_param1=="+list(messageDict.keys())[list(messageDict.values()).index(response_code)]+")) && global_error!=1-> \n")
                f.write("            atomic{Spd!channelType(0, 0, 0, "+response_code+", Responder_Cache."+response_code.lower()+");\n")
                f.write("                   //ERROR 1 // respondIfReady 2\n")
                if response_code=="PSK_FINISH_RSP":
                    f.write("                   //PSK_FINISH 2\n")
                f.write("                   assert(global_error==0);}\n")
                f.write("        :: global_error==1 ->\n")
                f.write("            atomic{Spd!channelType(0, 0, ResponseNotReady+1, ERROR, 0);\n");
                f.write("                   ERROR_response_code="+response_code+";\n")
                f.write("                   //ERROR 1\n")
                f.write("                   assert(global_error==1);}\n")
                if "VERSION" not in response_code and "CAPABILITIES" not in response_code and "ALGORITHMS" not in response_code:
                    f.write("        :: global_error==1 ->\n")
                    f.write("            atomic{Spd!channelType(0, 0, ResponseNotReady, ERROR, 0);\n")
                    f.write("                   RESPOND_IF_READY_response_code="+response_code+";\n")
                    f.write("                   //ERROR 1\n")
                    f.write("                   assert(global_error==1);}\n")
                if "HEARTBEAT" in response_code:
                    f.write("        :: global_error==1 ->\n")
                    f.write("            atomic{Spd!channelType(0, 0, InvalidSessionID, ERROR, 0);\n")
                    f.write("                   ERROR_response_code="+response_code+";\n")
                    f.write("                   //ERROR 1\n")
                    f.write("                   assert(global_error==1);}\n")
                # if "ENCAPSULATED" in response_code:
                #     f.write("        :: (response_signal!="+list(messageDict.keys())[list(messageDict.values()).index(response_code)]+" || (response_signal==RESPOND_IF_READY && response_param1=="+list(messageDict.keys())[list(messageDict.values()).index(response_code)]+")) ->\n")
                #     f.write("            atomic{Spd!channelType(0, 0, RequestInFlight, ERROR, 0);\n")
                #     f.write("                   //ERROR 1\n")
                #     f.write("                   ERROR_response_code="+response_code+";\n")
                #     f.write("                   }\n")
                else:
                    f.write("        :: else ->\n")
                    f.write("            printf(\""+response_code+" error\\n\");\n")
                f.write("        fi\n")
                # f.write("        if\n")
                # f.write("        :: global_error==1 -> if_error=1;\n")
                # f.write("        :: else -> if_error=0;\n")
                # f.write("        fi\n")
                f.write("        goto START;\n")
                f.write("    }\n")
        # f.write(sub.get('Id')+":\n")
    if "Reque" in strr and "VEN" not in strr:
        f.write("LEAVE:\n")
    f.write("}\n")

# f.write("        if\n")
# f.write("        :: global_error==1 -> if_error=1;\n")
# f.write("        :: else\n")
# f.write("        fi\n")


def main(xmlfile):
    f_write=open(sys.argv[1]+".pml","w")
    ds = AcesDiagram(xmlfile)
    for (name, nodes, edges) in ds.diagram_iter():
        print(name)
        agents=[]
        import pprint
        # pprint.pprint(nodes)
        addHeader(f_write, "header.pml")
        for node in nodes:
            if node['Type']=='Agent':
                # print(node['Props']['BpmnName'])
                agents.append(node)
                agent2Proctype(node['Props']['BpmnName'], f_write, node['Subs'], nodes, edges)
        addInit(f_write, agents, nodes)
        addProperties(f_write)

    
    f_write.close()


if __name__ == "__main__":
    print(messageDict)
    if len(sys.argv) != 2:
        print('@ error: ')
        sys.exit(1)
    main(sys.argv[1])
    sys.exit(0)

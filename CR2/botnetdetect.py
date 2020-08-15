import dpkt
import glob
from functools import reduce
import csv
import numpy as np
import socket
import numpy as np
import tensorflow as tf
from tensorflow import keras
import glob
import tqdm
from keras.regularizers import l2
import os
import sys

test_path = sys.argv[1]
print(test_path)
from dpkt.compat import compat_ord

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def vectorize(data):
    """
    data needs to be a row
    """
#     print(data,type(data))
    vector=[]
    #sip
    temp=[int(ip) for ip in data['sip'].split('.')]
    for e in temp:
        vector.append(e)
    #sport
    vector.append(int(data['sport']))
    #dip
    temp=[int(ip) for ip in data['dip'].split('.')]
    for e in temp:
        vector.append(e)
    #dport
    vector.append(int(data['dport']))
    #byte_count
    vector.append(int(data['byte_count']))
    #tos
    vector.append(int(data['tos']))
    #proto
    vector.append(0) if data['proto']=='TCP' else vector.append(1)
    #duration
    vector.append(float(data['duration']))
    #totalbytes
    vector.append(int(data['totalbytes']))

    labels = []
    labels.append(data['sip'])
    labels.append(data['dip'])
    labels.append(data['ts'])
    return vector,int(data['label']), labels

#Run this to get train test split datset in the form of csv
def get_csv(path = './', output = 'train.csv', single = False):
    
    names = glob.glob(path + '*/*/*/*.*',recursive=True) if single == False else [path]

    train = []
    train_labels = []
    labels = []
    ext = []
    with open(output, 'w') as csv_train:
        train_writer=csv.writer(csv_train)
        train_writer.writerow(['sip','sport','dip','dport','timestamp', 'byte_count','tos','proto','duration','totalbytes'])
        ext = []
        done = 0
        dic = {}
        key_list = ['sip','sport','dip','dport','byte_count','tos','proto','duration','totalbytes','label', 'ts']
        for filename in names:

            file = open(filename,'rb')
            try:
                pcap = dpkt.pcapng.Reader(file)
                print('pcapng read')
            except:
                file=open(filename,'rb')
                pcap = dpkt.pcap.Reader(file)
                print('pcap read')
            
            flows = {}

            for timestamp, buf in pcap:
                
                eth = dpkt.ethernet.Ethernet(buf)
                if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
                    try:
                        eth.data = dpkt.ip.IP(eth.data)
                    except:
                        continue

                # Now grab the data within the Ethernet frame (the IP packet)
                ip = eth.data
                
                # extract IP and transport layer data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                
                try:
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
                except:
                    try:
                        ip.data = dpkt.udp.UDP(ip.data)
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    except:
                        ext.append([timestamp, src_ip, dst_ip, 0])
                        continue

                # store flow data
                flow = sorted([(src_ip, src_port),
                                (dst_ip, dst_port) # comment this to get srcbytes
                              ])
                flow = (flow[0], 
                            flow[1]  #comment this to get srcbytes
                        )
                try:
                    flow_data = {
                        'byte_count': len(eth),
                        'ts': timestamp,
                        'tos': ip.tos,
                        'proto': ip.get_proto(ip.p).__name__,
                        'sport': src_port,
                        'dport': dst_port
                    }
                    done += 1
                except:
                    try:
                        flow_data = {
                            'byte_count': len(eth),
                            'ts': timestamp,
                            'tos': ip.tos,
                            'proto': 'IP',
                            'sport': src_port,
                            'dport': dst_port
                        }
                    except:
                        ext.append([timestamp, src_ip, dst_ip, 0])
                        continue

                if flows.get(flow):
                    flows[flow].append(flow_data)
                else:
                    flows[flow] = [flow_data]

            count=0
            for k in flows.keys():
            #     dumpFlow(flows, k, ct)
                bytes = reduce(lambda x, y: x+y,
                                map(lambda e: e['byte_count'], flows[k]))
                duration = sorted(map(lambda e: e['ts'], flows[k]))
                duration = duration[-1] - duration[0]
                target=0
                if 'Botnet' in filename.split('/'):
                    target=1
                for obj in flows[k]:
                    obj['duration']=duration
                    obj['totalbytes']=bytes
                    obj['label']=target
                    count+=1

            print(count)

            count=0
            for key in flows.keys():
                for i in flows[key]:
                    rec = [key[0][0],key[0][1],key[1][0],key[1][1],i['byte_count'],i['tos'],i['proto'],i['duration'],i['totalbytes'],i['label'],i['ts']]
                    
                    for j in range(len(rec)):
                        dic[key_list[j]] = rec[j]
                  
                    train_writer.writerow([key[0][0],key[0][1],key[1][0],key[1][1],i['ts'],i['byte_count'],i['tos'],i['proto'],i['duration'],i['totalbytes']])
                    a,b,c = vectorize(dic)
                    train.append(a)
                    train_labels.append(b)
                    labels.append(c)
                    count+=1
            print(filename,' read successfully')

    return train, train_labels, labels, ext

def write_result(arr, f):
    arr[3] = 'Botnet' if arr[3] == 1 else 'Benign'
    f.write(f"{arr[0]},{arr[1]},{arr[2]},{arr[3]}\n")

class Model():

  def __init__(self):
    self.model = keras.Sequential()
    self.model.add(keras.layers.Dense(128, activation='relu', kernel_initializer = 'he_uniform' , kernel_regularizer = l2(1e-4), input_shape = (15,)))
    self.model.add(keras.layers.Dense(128, activation='relu', kernel_initializer = 'he_uniform' , kernel_regularizer = l2(1e-4)))
    self.model.add(keras.layers.Dense(128, activation='relu', kernel_initializer = 'he_uniform' , kernel_regularizer = l2(1e-4)))
    self.model.add(keras.layers.Dense(1, kernel_initializer = 'he_uniform'))

    self.model.compile(optimizer= 'adam', 
              loss=tf.losses.BinaryCrossentropy(from_logits = True),
              metrics=['accuracy'])
    
  def dataloader(self):
    train, train_labels, _, _ = get_csv()

    train = np.array(train)
    train_labels = np.array(train_labels)

    np.save('./x_train.npy', train)
    np.save('./y_train.npy', train_labels)
    return train, train_labels


  def train(self):
    if not os.path.exists('./x_train.npy'):
        x,y = self.dataloader()
        x = np.array(x)
        y = np.array(y)
    else:
        x = np.load('x_train.npy')
        y = np.load('y_train.npy')

    x = (x-np.mean(x))/np.std(x)

    self.model.fit(
      x, y ,
      epochs=1
    )

    self.model.save_weights('wts_botnet.h5', save_format = 'h5')

    # stores all text files in the memory
  def test(self, pth):
    self.model.load_weights('wts_botnet.h5')
    
    x,y,labels,ext = get_csv(pth, 'test.csv', True)
    x = np.array(x)
    y = np.array(y)

    x = (x-np.mean(x))/np.std(x)
    
    for i in tqdm.tqdm(range(0, len(y),32)):
        ret = self.model.predict(x[i:min(i+32,len(y)),:])
        for k in range(len(ret)):
            labels[i+k].append((ret[k] >= 0)[0])

    with open('result.txt', 'w') as f:
        for elem in ext:
            write_result(elem, f)
        for elem in labels:
            write_result(elem, f)

mod = Model()
if not os.path.exists('./wts_botnet.h5'):
  mod.train()
  mod.test(test_path)
else:
  mod.test(test_path)


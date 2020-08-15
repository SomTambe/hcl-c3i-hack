# Botnet Detection Model by Hackermen69

This folder contains a python script that can be used for classifying benign and botnet traffics based on the network packets extracted. The neural network has been built using Tensorflow Machine Learning framework. 

## How to use :

```
pip install -r requirements.txt
python botnetdetect.py absolute_path_for_pcap_file
```  
**Note** : Run the program in the same folder as the program itself, so as to load saved weights. 

The script will :-

* Run on the provided file.
* Extract the required features and creates a feature vector which is fed to the neural network for classification.
* Return a result.txt file that contains the information of the traffic being benign or botnet in the format *<Timestamp> <SourceIP> <DestinationIP> <Botnet or Benign>*

**Note** : The output in result.txt is not in ascending order of timestamp. Please check the predictions with respect to timestamp of the packet.

## Libraries Used:

The following libraries were used to make the model:

* Tensorflow
* numpy
* dpkt
* glob
* os
* sys
* sklearn
* csv
* tqdm
* socket

## References:

* *Network Traffic Based Botnet Detection Using Machine Learning By Anand Ravindra Vishwakarma*  [Link](https://scholarworks.sjsu.edu/cgi/viewcontent.cgi?article=1917&context=etd_projects)

* *Parsing Pcap files using dpkt python* [Link](https://stackoverflow.com/questions/6337878/parsing-pcap-files-with-dpkt-python)

* *Dpkt Python Docs* [Link](https://dpkt.readthedocs.io/en/latest/)

* *sklearn.feature_extraction.FeatureHasher* [Link](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.FeatureHasher.html)

## Team Members: 

* Yatharth Goswami (IITK, 191178)
* Som Tambe (IITK, 190847)
* Atharv Singh Patlan (IITK, 190200)
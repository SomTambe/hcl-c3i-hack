# Malware Detection Model by Hackermen69

This folder contains a python script that can be used for classifying benign and malicious files. The neural network has been built using Tensorflow Machine Learning framework.

## How to use :

1. Run the script *MalwareDetection.py*
2. Provide the path to the database folder.  

The script will :-

* Run on all the files in the database.
* Extract the required features and creates a feature vector which is fed to the neural network for classification.
* Return a output.csv file that contains the information of the file being benign or malicious in the format *<File Hash> <Malicious or benign>*

## Libraries Used:

The following libraries were used to make the model:

* Tensorflow
* numpy
* re
* glob
* sklearn
* os
* csv
* time
* tqdm

## References:

* *Static Malware Detection Using Deep Neural Networks On Portable Executables by Piyushaniruddha Puranik*  [Link](https://digitalscholarship.unlv.edu/cgi/viewcontent.cgi?article=4747&context=thesesdissertations)

* *EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models* [Link](https://arxiv.org/pdf/1804.04637.pdf)

* *PE File Format* [Link](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)

* *sklearn.feature_extraction.FeatureHasher* [Link](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.FeatureHasher.html)

## Team Hackermen69 members:
1. Yatharth Goswami, IITK, 191178
2. Som Tambe, IITK, 190847
3. Atharv Singh Patlan, IITK, 190200

forensic
========

Conduct user defined heuristic analysis based on information extracted by volatility plugins


__Interface__:

Please refer to wiki page for details about adding new heuristic rules.


__Usage__:

1) Install volatility (https://github.com/volatilityfoundation/volatility.git)

2) Install dependency package (conf_d):

    sudo apt-get install python-pip
    
    sudo pip install conf_d
or: 

    git clone https//github.com/josegonzalez/python-conf_d.git
    
    cd python-conf_d
    
    sudo python setup.py install

3) Install mongodb&pymongo if you want to enable reusing volatility results, it was *disabled* by default

4) Get this tool and start using it:

    git clone https://github.com/xia0pin9/forensic.git
    
    cd forensic
    
    python forensic.py -f be2.vmem
    
    
__Next plan__:

1) Add heuristic rules related to dlls, modules, handles (trying to find suspicious paths)

2) Add heuristic rules related to *autorun* entries

3) Add supporting interface for user defined IOC or other context information, e.g., given particular domain or host information, list related process, threads, modules, handles etc.

__Feadback__:

Please send your feadback and feature requests through the following *issues* link:

`https://github.com/xia0pin9/forensic/issues`

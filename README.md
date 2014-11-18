forensic
========

Conduct user defined heuristic analysis based on information extracted by volatility plugins


__Interface__ (for adding new heuristic rules):

1) Add new rule in rules/heurictics.conf

  First block in this file is to specify rule needed to be checked and output messages.
  New heuristic rule can be added as another block, rule name can be arbitraty but should start with known category name and a dash "/", e.g., processes/similarity

2) Add corresponding handle function in handles/processes directory

  The file name and function name should be the same as the one specified in the above rules, all the function should follow the same input and output structure. For input, the function needs to handle three parameter: info (processes, services, etc.) list, corresponding rule, output message structure. For output, the function needs to prepare approriate output message and return the message in the end. The handle function can use arbitrary key defined in the above rule, can specify output any format of message.



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

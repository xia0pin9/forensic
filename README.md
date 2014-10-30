forensic
========

Conduct user defined heuristic analysis based on output information extracted by volatility plugins


__Interface__ (for adding new heuristic rules):

1) Add new rule in rules/heurictics.conf

  First block in this file is to specify rule needed to be checked and output messages.
  New heuristic rule can be added as another block, rule name can be arbitraty but should start with known category name and a dash "/", e.g., processes/similarity

2) Add corresponding handle function in handles/processes directory

The file name and function name should be the same as the one specified in the above rules, all the function should follow the same input and output structure. For input, the function needs to handle three parameter: info (processes, services, etc.) list, corresponding rule, output message structure. For output, the function needs to prepare approriate output message and return the message in the end. The handle function can use arbitrary key defined in the above rule, can specify output any format of message.


__Usage__:

1) Install dependency package:

    git
   
    volatility (https://github.com/volatilityfoundation/volatility.git)

    conf_d (https://github.com/josegonzalez/python-conf_d.git)

2) Install mongodb&pymongo if you want to enable reusing volatility results, *disabled* by default

3) Specify memdump image and start using this tool:

    python forensic.py -f be2.vmem

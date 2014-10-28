forensic
========

Conduct user defined heuristic analysis based on output information extracted by volatility plugins


__Interface__ (for adding new heuristic rules):

1) Add new rule in rules/heurictics.conf
  First block in this file is to specify rule needed to be checked and output messages.
  New heuristic rule can be added in the end, rule name can be arbitraty but has to start with known category name and a dash "/", e.g., processes/similarity

2) Add corresponding handle function in handles/processes directory, the file name and function should be the same as the one specified in the above rules.


__Usage__:

1) Install volatility

2) Install mongodb if you want to enable reusing volatility results, disabled by default

3) Specify image and start using this tool.

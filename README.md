# CSC503-Project

Steps:
- install ```pipenv``` by using ```pip``` or package manager like ```brew``` or ```apt```
- run ```pipenv install```
- in ```src/smellDetector.py```, edit line ```150, 155, 485```
- in ```src/AnsibleSmellDetector.py``` edit line ```268,269```
- in ```ymlPaths/github.txt```, edit all the file locations
- run both the ```src/AnsibleSmellDetector.py``` and ```src/smellDetector.py```
- outputs will be in ```./facts-ansible.pl``` and ```./facts-python.pl```
- append the rules in those files from ```./rules.pl```

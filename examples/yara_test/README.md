# Yara Test Directory
Welcome to the yara test directory, this is just so we can run unit tests. If you're going to use zat with yara rules do the following:

### Download official yara rules
    $ git clone https://github.com/Yara-Rules/rules

### Usage
When creating the zat YaraRules class simply provide the path to the index file in the yara repository.


    ...
    yara_rules = YaraRules(rule_index=/path/to/rules/index.yar)
    matches = yara_rules.match('/path/to/file')

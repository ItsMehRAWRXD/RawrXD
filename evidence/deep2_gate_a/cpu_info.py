import os
print('PROCESSOR_IDENTIFIER:', os.environ.get('PROCESSOR_IDENTIFIER', '?'))
print('PROCESSOR_ARCHITECTURE:', os.environ.get('PROCESSOR_ARCHITECTURE', '?'))
print('PROCESSOR_LEVEL:', os.environ.get('PROCESSOR_LEVEL', '?'))
print('NUMBER_OF_PROCESSORS:', os.environ.get('NUMBER_OF_PROCESSORS', '?'))

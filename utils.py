import pickle
from evmdasm import EvmBytecode

model = None # yours model
tr = None # yours threshold
trfrm = None # yours vectorizer

def decompile(_bytecode: str):
    """
    Декомпилирует байткод в опкод
    :param _bytecode: байткод контракта из нового блока
    :return: опкоды в виде str
    """
    print('Decompling to opcodes')
    disassembler = EvmBytecode(_bytecode)
    opcode = disassembler.disassemble().as_string
    print('Normalizing opcode')
    opcode_normalized = opcode.replace(' \n', '\n').replace(' ', ' 0x')
    return opcode_normalized.lower()

def inference(_opcode: str):
    """
    Инференс вашей модели
    :param _opcode:
    :return: класс смарт-контракта
    """
    y_proba = None # скор вашей модели
    return int(y_proba > tr)
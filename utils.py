import pickle
from evmdasm import EvmBytecode
from catboost import CatBoostClassifier

model = CatBoostClassifier().load_model('Model/catboost_clf_checkpoint.cbm', format='cbm')
tr = 0.8
trfrm = pickle.load(open('Model/vectorizer.pkl', 'rb'))


def decompile(_bytecode: str) -> str:
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


def inference(_opcode: str, debug: bool = False) -> int:
    """
    Инференс вашей модели
    :param _opcode:
    :return: класс смарт-контракта
    """
    opcode_transformed = trfrm.transform([_opcode])
    probs = model.predict_proba(opcode_transformed)
    if debug:
        print(f"Probabilities: {probs}")
    y_proba = probs[:, 1]  # pos class prob
    return int(y_proba > tr)

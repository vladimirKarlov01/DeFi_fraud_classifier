from utils import decompile, inference
from web3 import Web3
from keys import NODE_ADDRESS
from multiprocessing import Process, Manager, Queue, Lock
import time

def get_new_trns(q_out: Queue):
    """
    !Work in separate process

    q_out: Queue with new deploys

    Функция для прослушивания последних блоков в блокчейне, если новая транзакция - деплой, то записываем в очередь

    Ваша обработка отключения от ноды +1 балл
    """
    i = 1
    wss = NODE_ADDRESS
    w3 = Web3(Web3.WebsocketProvider(wss))
    print(f'Node Connection - {w3.is_connected()}')
    print(f'Connection attempt - {i}')
    while True:
        try:
            start_time = time.time()
            trns_block = w3.eth.get_block('new_block', full_transactions=True).transactions # считываем батч новых транз
            for trns in trns_block:
                if trns['to'] is None: # смотрим что транзакция это деплой
                    q_out.put(trns)
            end_time = time.time()
            print(f"{end_time - start_time} per 1 batch")
        except Exception as e:
            #TODO Ваша обработка нарушения соединения с нодой
            pass

def analyze_trns(q_in: Queue):
    """
    !Work in separate process
    
    q_in: Queue with new deploys to analyze
    
    Функция для анализа деплоев, принтит результат деплоя а именно
    1) Адресс контракта
    2) Хеш транзакции
    3) Результат классификации
    +1 балл работа с дублирующимися транзакциями
    +1 балл за имплементацию работы с ML моделью
    :param q_in:
    :return:
    """
    #TODO Ваша имплементация
    trns_address = None
    trns_hash = None
    y_class = None
    print(f"Address - {trns_address}"
          f"Hash - {trns_hash}"
          f"Is_malicious? {y_class}")

if __name__ == '__main__':
    print('Hello there!')
    # Queue for new pending trns
    new_deploys_trns_queue = Queue()
    new_deploys_tracker = Process(name='Mempool Scanner',
                              target=get_new_trns,
                              args=(new_deploys_trns_queue, ),
                              daemon=True)

    deploy_analyzer = Process(name='Mempool analyzer',
                              target=analyze_trns,
                              args=(new_deploys_trns_queue, ),
                              daemon=True)

    # start
    new_deploys_tracker.start()
    deploy_analyzer.start()



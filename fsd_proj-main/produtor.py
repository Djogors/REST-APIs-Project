import socket
import threading
import random

# Definição de constantes
PORT = 5050
HOST = '127.0.0.1'
ADDR = (HOST, PORT)

BYTES = 1024
FORMAT = 'utf-8'
DELIMITER = ';;'

lock = threading.RLock()

def generate_stock():
    # Definir as categorias fixas para cada item
    categories = {
        'morangos': 'fruta',
        'martelos': 'ferramentas',
        'maçãs': 'fruta',
        'pêras': 'fruta',
        'serras': 'ferramentas',
    }

    items = list(categories.items())
    
    # Selecionar um número aleatório de itens
    num_items = random.randint(1, len(categories))

    selected_items = random.sample(items, num_items)
    
    # Criar o dicionário final com quantidades e preços aleatórios
    stock = {}
    
    for item, category in selected_items:
        # Gerar quantidade aleatória entre 50 e 500 kg
        qtty = random.randint(50, 500)
        # Gerar preço aleatório entre 1.00 e 10.00 euros
        price = round(random.uniform(1.00, 10.00), 2)
        # Adicionar ao dicionário
        stock[item] = (qtty, price, category)
    
    return stock

# Stock inicial
stock = generate_stock()

def start():
    print("[STARTING] Produtor está a dar start...")
    producer.listen()
    print(f"[ESPERA] Produtor está à espera em {ADDR}.")
    while True:
        # Aceitar conexão
        conn, addr = producer.accept()
        # Iniciar uma thread para cada conexão
        thread = threading.Thread(target=handle_marketplace, args=(conn, addr))
        thread.start()

def handle_marketplace(conn, addr):
    connected = True
    while connected:
        # Receber pedido to marketplace
        msg = conn.recv(BYTES).decode(FORMAT)
        # Se receber
        if msg:
            msg_split = msg.split(DELIMITER)
            # Se a mensagem estiver repartida em 3, exemplo: dsadas;;dsadsa;;dsadsa
            if len(msg_split) == 3:
                option = msg_split[0]
                if option == "comprar":
                    product, quantity = msg_split[1:3]
                    # Remover espaço vazio e meter as letras minusculas.
                    product = product.strip().lower()
                    # Se o produto existir no stock
                    if product in stock.keys():
                        # Verificar se a quantidade pode ser convertida para inteiro.
                        try:
                            quantity = int(quantity)
                        except ValueError:
                            conn.sendall(f'[ERRO] A quantidade tem de ser um número inteiro!'.encode(FORMAT))
                            continue

                        if 0 < quantity <= stock[product][0]:
                            with lock:
                                # Substituir a tuple
                                stock[product] = (stock[product][0]-quantity, stock[product][1], stock[product][2])
                                # Enviar mensagem de confirmação
                                conn.sendall(f'[COMPRA] Compra concluída com sucesso: {quantity} {product}!'.encode(FORMAT))
                                continue
                        # Se não houverem produtos suficientes em stock
                        else:
                            conn.sendall("[ERRO] Não existem produtos suficientes em stock!".encode(FORMAT))
                            continue
                    # Se o produto não existir no catálogo
                    else:
                        conn.sendall("[ERRO] Não existe esse produto no catálogo!".encode(FORMAT))
                        continue
                # Se a opção for global
                elif option == "global":
                    _, category_user = msg_split[1:3]
                    msg_to_send = ""
                    for product, (quantity, price, category) in stock.items():
                        if category_user == category:
                            msg_to_send = f"{msg_to_send}-{product};;{quantity};;{price*quantity}"
                    if msg_to_send == "":
                        msg_to_send = "0"
                    conn.sendall(msg_to_send.encode(FORMAT))
                    continue
                # Se a opção não fôr válida
                else:
                    conn.sendall("[ERRO] Opção não válida".encode(FORMAT))
                    continue
            # Se a mensagem estiver repartida em 1, exemplo: dasdsa
            elif len(msg_split) == 2:
                option, category_user = msg_split
                if option == "listar":
                    # Header
                    response = (f"\n{'Produto':<10} {'Quantidade':<10} {'Preço':<15}\n")
                    response += "-"*30 + "\n"
                    # Formatar tabela
                    for product, (quantity, price, category) in stock.items():
                        if category_user == category:
                            response += (f"{product.capitalize():<10} {quantity:<10} €{price:<10.2f}\n")
                    
                    conn.sendall(response.encode(FORMAT))
                    continue
                else:
                    conn.sendall("[ERRO] Opção não válida!".encode(FORMAT))
                    continue
            elif len(msg_split) == 1:
                option = msg_split[0]
                if option == "listar":
                    # Header
                    response = (f"\n{'Produto':<10} {'Quantidade':<10} {'Preço':<15}\n")
                    response += "-"*30 + "\n"
                    # Formatar tabela
                    for product, (quantity, price, _) in stock.items():
                        response += (f"{product.capitalize():<10} {quantity:<10} €{price:<10.2f}\n")
                        
                    conn.sendall(response.encode(FORMAT))
                    continue
                else:
                    conn.sendall("[ERRO] Opção não válida!".encode(FORMAT))
                    continue
            else:
                conn.sendall("[ERRO] Número de argumentos inválido!".encode(FORMAT))
                continue
        # Se não receber
        else:
            connected = False
    # Fechar a conexão
    conn.close()

# Criação da socket
producer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

producer.bind(ADDR)

start()

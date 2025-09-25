import socket
import threading
import struct
import os
import json
import shutil # 인터페이스 게이지바 구현
import time # sleep 함수 투입.
import sys # 출력버퍼를 비우는 역할
from tqdm import tqdm # 멀티 쓰레딩만 처리된 서버 전송 파일.
import logging # 로그 처리할 때, 필요한 라이브러리 
import time

# 객체지향으로 짜주기..?
def save_data_to(data, filename): #JSON파일 수정본 저장.
    with open(filename, "w", encoding = "utf-8") as file:
        json.dump(data, file, ensure_ascii= False, indent =4) # indent는 들여쓰기.

def update_received_files_in_json(file_name, file_size, addr):
    """JSON 파일에 수신된 파일 정보를 추가합니다."""
    try:
        # 기존 데이터 로드
        data = load_data(FILENAME)
        if not data:
            data = default_data
        
        # 새 파일 정보 추가
        new_file_info = {
            "Name": file_name,
            "File_Size": f"{file_size} bytes",
            "Sender": f"{addr[0]}:{addr[1]}"
        }
        if "Received_Files" not in data:
            data["Received_Files"] = []
        data["Received_Files"].append(new_file_info)
        
        # 업데이트된 데이터 저장
        save_data_to(data, FILENAME)
        logging.info(f"파일 정보 저장: {new_file_info}")
    except Exception as e:
        logging.error(f"JSON 업데이트 중 오류 발생: {e}")


def get_local_ip(): # 자신의 로컬주소를 반환.
    """로컬 IP주소를 감지하여 반환합니다."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"[ERROR] IP 감지 실패 : {e}")
        return "127.0.0.1"

def load_data(filename): # JSOM 파일 로드
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print("JSON 파일을 찾을 수 없습니다.")
        return

# 기본 설정
FILENAME = "Server_data.json"
HEADER_FORMAT = "I"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
BUFFER_SIZE = 1024 * 1024 * 1024

default_data = {
    "log_settings": {
        "level": "INFO",
        "log_file_path": "Server-log.log"
    },
    "Server_setting": {
        "host": "",
        "port": 1234,
        "save_path": "C:"
    },
    "Saved_Files" : {
        "Name" : "",
        "File_Size" : ""
    },
    "Received_Files": [
        {
            "Name": "example.txt",
            "File_Size": "12345 bytes",
            "Sender": "192.168.1.10:54321"
        }
    ]
}
# JSON 파일에서 설정 불러오기
data = load_data(FILENAME)
if not data:
    data = default_data  # JSON 파일이 없으면 기본값 사용
    save_data_to(data, FILENAME)
else:
    # JSON 데이터와 변수 동기화
    host = data["Server_setting"]["host"]
    port = data["Server_setting"]["port"]
    save_path = data["Server_setting"]["save_path"]

connected_clients = {}
received_files = []
server_socket = None
server_running = False  # 서버 실행 상태를 나타내는 플래그
drive_path = "C:/"
total, using, free = shutil.disk_usage(drive_path)
# 여기서부터는 로그 설정.
logger = logging.getLogger(name='MyLog')
logger.setLevel(logging.INFO) ## 경고 수준 설정

formatter = logging.Formatter('|%(asctime)s||%(name)s||%(levelname)s|\n%(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S'
                             )
file_handler = logging.FileHandler('Server-log.log')
file_handler.setFormatter(formatter) # 텍스트 포멧 설정
logger.addHandler(file_handler) # 핸들러 등록

def generate_tree_structure(directory, indent=""):
    try:
        entries = os.listdir(directory)
        entries.sort()  # Sort entries for consistent output
        tree_lines = []
        for i, entry in enumerate(entries):
            full_path = os.path.join(directory, entry)
            is_last = i == len(entries) - 1
            prefix = "└── " if is_last else "├── "
            tree_lines.append(f"{indent}{prefix}{entry}")
            if os.path.isdir(full_path):
                sub_indent = "    " if is_last else "│   "
                tree_lines.extend(generate_tree_structure(full_path, indent + sub_indent))
        return tree_lines
    except Exception as e:
        return [f"Error reading directory: {e}"]
    
def handle_list_request_1001(client_socket, addr):
     # Generate folder structure from the specified path
      # mydata = f"{total / (1024 ** 3):.2f}, {using / (1024 ** 3):.2f}, {free / (1024 ** 3):.2f}\n"
      # client_socket.send(mydata.encode('utf-8'))#
        tree_structure = generate_tree_structure(save_path)
        response = "\n".join(tree_structure)
    # Send the response to the client
        client_socket.send(response.encode('utf-8'))
        if addr in connected_clients:
            del connected_clients[addr]
        print("계속 하시려면 [Enter]를 눌러주세요.")
        start_server()

def handle_left_save_space(client_socket, drive_path, addr):
    """서버의 저장 공간 정보를 클라이언트로 전송"""
    try:
        total, used, free = shutil.disk_usage(drive_path)
        data = f"{total / (1024 ** 3):.2f}, {used / (1024 ** 3):.2f}, {free / (1024 ** 3):.2f}"
        
        # 데이터 크기 전송
        data_bytes = data.encode('utf-8')
        data_length = len(data_bytes)
        client_socket.sendall(struct.pack("I", data_length))  # 데이터 크기 전송
        # 실제 데이터 전송
        client_socket.sendall(data_bytes)
        print(f"[SERVER] 데이터 전송 완료: {data}")
    except Exception as e:
        print(f"[SERVER ERROR] 저장 공간 정보 전송 중 오류: {e}")
    finally:
        if client_socket:
            client_socket.close()
        if addr in connected_clients:
            del connected_clients[addr]
        logging.info(f"클라이언트에게 저장 공간 전송")
        start_server()


def handle_delete_request(client_socket, data, addr):
    # 데이터 길이 읽기.
    data_length = int.from_bytes(client_socket.recv(4), 'little')
            # 파일 경로 읽기
    file_path = client_socket.recv(data_length).decode('utf-8')
    delete_this_path = save_path + "\\" + file_path
    if os.path.exists(delete_this_path):
        os.remove(delete_this_path)
        client_socket.send("파일 삭제 성공".encode('utf-8'))
    else:
        client_socket.send("파일이 서버의 저장공간 내에 존재하지 않습니다.".encode('utf-8'))
    if addr in connected_clients:
        del connected_clients[addr]
    print("계속 하시려면 [Enter]를 눌러주세요.")
    start_server()


def handle_rename_request(client_socket, data, addr):
    data_length_old = int.from_bytes(client_socket.recv(4), 'little')
    old_name = client_socket.recv(data_length_old).decode('utf-8')

    data_length_new = int.from_bytes(client_socket.recv(4), 'little')
    new_name = client_socket.recv(data_length_new).decode('utf-8')

    old_path = os.path.join(save_path, old_name)
    new_path = os.path.join(save_path, new_name)
    try:
        os.rename(old_path, new_path)
        logging.info(f"파일 이름 변경 완료: {old_name} -> {new_name}")
        client_socket.send("파일 이름 변경 완료".encode('utf-8'))
    except FileNotFoundError:
        logging.error(f"파일 이름 변경 실패: {old_name} (존재하지 않음)")
        client_socket.send("파일 이름 변경 실패".encode('utf-8'))
    finally:
        if addr in connected_clients:
            del connected_clients[addr]
        print("계속 하시려면 [Enter]를 눌러주세요.")
        start_server()


def recv_all(client_socket, length):
    data = b""
    while len(data) < length:
        try:
            packet = client_socket.recv(length - len(data))
            if not packet:
                raise ConnectionError("데이터 수신 중 연결이 끊어졌습니다.")
            data += packet
        except Exception as e:
            print(f"[ERROR] 데이터 수신 중 에러 발생: {e}")
            break
    return data


def handle_file_transfer_3003(client_socket, data, addr):
    try:
        file_count = struct.unpack("I", client_socket.recv(4))[0]
        print(f"[INFO] 클라이언트가 요청한 파일 개수 : {file_count}개")
        for _ in range(file_count):
            data_length = struct.unpack("I", client_socket.recv(4))[0]
            file_path = client_socket.recv(data_length).decode('utf-8')
            full_path = os.path.join(save_path, file_path)
            if not os.path.exists(full_path):
                error_message = "파일이 존재하지 않습니다." 
                client_socket.send(len(error_message).to_bytes(4, 'little'))
                client_socket.send(error_message.encode('utf-8'))
                return
            file_size = os.path.getsize(full_path)
            client_socket.send(file_size.to_bytes(8, 'little'))
            with open(full_path, 'rb') as f:
                while (1):
                    data = f.read(4096)
                    if not data:
                        break
                    client_socket.sendall(data)
            print(f"\n파일 전송 완료 : {full_path}")
            # 여기서 다시 시작하는 뭔가 함수를 생성해서 넣어야되나?ㄴ
    except Exception as e:
        error_message = f"에러 발생 : {str(e)}"
        client_socket.send(len(error_message).to_bytes(4, 'little'))
        client_socket.send(error_message.encode('utf-8'))
        print(f"파일 전송 중 에러: {str(e)}")
    finally:
        if addr in connected_clients:
            del connected_clients[addr]
        print("계속 하시려면 [Enter]를 눌러주세요.")
        start_server()

# 클라이언트가 보낸 패킷 중 첫번째 처리.(이후 처리방향이 달라짐.)
def handle_packet(client_socket, addr): 
    """클라이언트로부터 패킷을 처리합니다."""
    try:
        # 이후 기존 패킷 처리 로직
        header = recv_all(client_socket, HEADER_SIZE)
        start_code = struct.unpack(HEADER_FORMAT, header)[0]
        print(f"\n{start_code}의 패킷 번호를 받았습니다.")
        # 시작 코드에 따라 처리
        if start_code == 1000:
            handle_client_1000(client_socket, addr)
        elif start_code == 1001:
            handle_list_request_1001(client_socket, addr)
        elif start_code == 3000:
            handle_left_save_space(client_socket, drive_path, addr)
        elif start_code == 3001:
            handle_delete_request(client_socket, data, addr)
        elif start_code == 3002:
            handle_rename_request(client_socket, data, addr)
        elif start_code == 3003:
            handle_file_transfer_3003(client_socket, data, addr)
        else:
            logging.warning(f"알 수 없는 시작코드: {start_code}")
    except ConnectionError as e:
        logging.info(f"클라이언트 {addr} 연결 종료: {e}")
    except Exception as e:
        logging.error(f"패킷 처리 중 오류: {e}")
    finally:
        if client_socket:
            client_socket.close()
        logging.info(f"클라이언트 {addr} 연결 종료")


# 패킷 전송
def send_packet(client_socket, start_code, data):
    data_length = len(data)
    header = struct.pack(HEADER_FORMAT, start_code, data_length)
    client_socket.sendall(header + data)

# 클라이언트 처리 함수 
# 여기다. 여기가 문제다.
def handle_client_1000(client_socket, addr ):
    print("\n==============================")
    print(f"\n[INFO] 클라이언트가 {addr}로부터 연결되었습니다.")
    logger.info(f'클라이언트가 {addr}로부터 연결')
    received_time = 0
    avg_speed = 0
    try:
        file_count = struct.unpack("I", client_socket.recv(4))[0] # 파일의 개수
        total_size = struct.unpack("Q", client_socket.recv(8))[0] # 총 파일의 크기
        print(f"[INFO] 클라이언트 {addr}가 보낼 파일 개수: {file_count}")
        print(f"[INFO] 클라이언트 {addr}가 보낼 총 데이터 크기 : {total_size} 바이트")
        if free < total_size + using:
            print(f"[Warning] 전송될 파일의 양이 남은 공간을 초과합니다.")  
            client_socket.sendall("[Warning] 전송될 파일의 양이 남은 공간을 초과합니다.".encode("utf-8"))
            return
        for i in range(file_count):
            file_name_size = struct.unpack("I", client_socket.recv(4))[0]
            file_name = client_socket.recv(file_name_size).decode("utf-8")
            file_size = struct.unpack("Q", client_socket.recv(8))[0]
            start_time = time.time()
            os.makedirs(save_path, exist_ok=True)
            with open(f"{save_path}/{file_name}", "wb") as file:
                received_size = 0
                with tqdm(total=file_size, unit="B", unit_scale=True, desc=f"Receiving {file_name}") as pbar:
                    try:
                        while file_size > received_size: #여기는 죄가 없다 data가 문제다
                            chunk = client_socket.recv(min(BUFFER_SIZE, file_size - received_size))
                            if not chunk:
                                raise ConnectionError("데이터 수신 중 연결이 끊어졌습니다.")
                            file.write(chunk)
                            received_size += len(chunk)
                            pbar.update(len(data))
                        else:
                            if received_size == file_size:
                                print(f"[INFO] 파일이 정상적으로 수신되었습니다: {file_name}")
                            else:
                                print(f"[ERROR] 파일 수신이 불완전합니다. {file_name}")
                    except socket.error as e:
                            print(f"[ERROR] 소켓 오류 발생: {e}")
                    # 추가적인 로그 처리나 에러 대응
            end_time = time.time()
            received_time = end_time - start_time
            avg_speed = received_size / received_time
            if received_size == file_size:
                received_files.append((file_name, addr))
                logger.info(f'파일 "{file_name}"을 수신받음 \n파일 사이즈 : {file_size}')
                print(f"[INFO] 파일이 저장되었습니다: {file_name}")
                update_received_files_in_json(file_name, file_size, addr)
            else:
                print(f"[ERROR] 파일 수신 실패: {file_name}")
    except socket.error as e:
        print(f"[ERROR] 소켓 오류 발생: {e}")
    except Exception as e:
        print(f"[ERROR] 일반 오류 발생: {e}")
    finally:
        if client_socket:
            client_socket.close()
        print(f"""\n받은 파일의 개수 :{file_count}
받은 파일의 총 크기 : {total_size / 1024/ 1024} MB  
총 파일을 수신받는데 걸린 시간 : {received_time} 초
평균 속도 : {avg_speed/ (1024* 1024):.2f} MB/s""")
        print(f"\n[INFO] 클라이언트 소켓이 {addr}와의 연결을 종료했습니다.")
        if addr in connected_clients: # 이게진짜 너무 컷다.. 이 한줄이..
            del connected_clients[addr]
        print("계속 하시려면 [Enter]를 눌러주세요.")
        start_server()

def check_drive_space(drive_path):
    print(f"드라이브: {drive_path}")
    print(f"총 용량: {total / (1024**3):.2f} GB")
    print(f"사용된 공간: {using / (1024**3):.2f} GB")
    print(f"남은 공간: {free / (1024**3):.2f} GB")
    return total, using, free

# 서버 시작
def start_server():
    global server_socket, server_running
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    #IPV4 , TCP 방식 할당.
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Time_wait 상태에서 포트 재사용을 가능하게 해줌.
    server_socket.bind((host, port))
    server_socket.listen()
    server_running = True
    print(f"[INFO] 서버가 {host}:{port}에서 실행 중입니다.")
    print("클라이언트의 접속을 기다리고 있습니다.")
    threading.Thread(target=accept_clients, daemon=True).start()
    # 쓰레드에 데몬쓰레드를 넣으면, 프로그램이 종료된 후에, 쓰레드도 자동으로 죽는다.
    # 클라이언트 연결 수락
def accept_clients():
    global server_running
    while server_running:
        try:
            client_socket, addr = server_socket.accept()
    # addr은 클라이언트의 IP와 포트번호를 저장하는 튜플.
    # 서버가 클라이언트의 연결 요청을 수락하고, 클라이언트와의 통신을 위해 새로운 소켓을 생성
            connected_clients[addr] = client_socket
            client_thread = threading.Thread(target=handle_packet, args=(client_socket, addr))
            client_thread.start()
        except OSError:
            break
    print("[INFO] 클라이언트 연결 수락이 종료되었습니다.")

# 사용자 메뉴
def display_menu():
    print("\n--- Menu ---")
    print(" 1. 서버 시작")
    print(" 2. 서버 설정")
    print(" 3. 클라이언트 리스트 보기")
    print(" 4. 저장된 파일 보기")
    print(" 5. 드라이브 남은 저장공간 보기")
    print(" 6. 종료")
    print("--------------")

def server_start_menu():
    global server_running, host
    host = get_local_ip()
    data["Server_setting"]["host"] = host # 이 2줄로 JSON데이터 저장.
    save_data_to(data, FILENAME)
    if server_running:
        print("\n[INFO] 서버가 이미 실행 중 입니다.")
        return 
    else:
        print("\n--- 서버가 실행 중입니다. --- ")
        logger.info(f'서버가 열림: {host}:{port}')
        start_server()
        while server_running:
            time.sleep(0.5)
            if not connected_clients:  
                decision = input("\n서버를 중지하시려면 exit 을 입력해주세요: ").strip().lower()
                if decision == 'exit':
                    print("\n[INFO] 서버를 중지합니다.")
                    stop_server()
                    return 
                elif decision == 'EXIT':
                    print("[INFO] 서버를 중지합니다.")
                    stop_server()
                    return
                elif decision == '':
                    continue
                else:
                    print("[ERROR] 잘못된 입력입니다.")

# 서버 중지
def stop_server():
    global server_socket, server_running
    if server_socket:
        server_running = False
        server_socket.close()
        server_socket = None
        print("[INFO] 서버가 종료되었습니다.")
    else:
        print("[INFO] 서버가 종료되었습니다.")
    logger.info(f'서버가 닫힘 : {host}:{port}')

def program_down():
    global server_socket, server_running
    if server_socket:
        server_running = False
        server_socket.close()
        server_socket = None
        print("[INFO] 프로그램이 종료되었습니다.")
        sys.exit(0)
    logger.info(f'프로그램 종료 : {host}:{port}')

# 서버 설정 메뉴
def display_server_settings():
    print("\n--- 서버 설정 ---")
    print(" 1. 현재의 IP주소/포트번호 출력")
    print(" 2. 포트 번호 변경")
    print(" 3. 현재의 저장 경로 출력")
    print(" 4. 저장 경로 변경")
    print(" 5. 뒤로 가기")
    print("------------------------")

def change_port():
    global port, data
    while True:
        try:
            new_port = int(input("새로운 포트 번호를 입력하세요: ").strip())
            if 0 <= new_port <= 65535:
                port = new_port
                data["Server_setting"]["port"] = port
                save_data_to(data, FILENAME)
                print(f"[INFO] 포트 번호가 {port}로 변경되었습니다.")
                logger.info(f'포트번호 변경: {port}')
                break
            else:
                print("[ERROR] 포트 번호는 0에서 65535 사이여야 합니다.")
        except ValueError:
            print("[ERROR] 유효한 숫자를 입력하세요.")
        
def change_save_path():
    global save_path, data
    new_path = input("새로운 저장 경로를 입력하세요: ").strip()
    if not os.path.exists(new_path):
        create = input(f"[INFO] {new_path} 경로가 존재하지 않습니다. 생성하시겠습니까? (y/n): ").strip().lower()
        if create == 'y':
            os.makedirs(new_path)
            print(f"[INFO] 경로가 생성되었습니다: {new_path}")
        else: 
            print("[INFO] 저장 경로 변경이 취소되었습니다.")
            return
    save_path = new_path
    data["Server_setting"]["save_path"] = save_path  # JSON 데이터 업데이트
    save_data_to(data, FILENAME)  # 변경 사항 저장
    print(f"[INFO] 저장 경로가 변경되었습니다: {save_path}")
    logger.info(f'저장경로 변경: {save_path}')

def now_path():
    print(f"현재의 저장공간은 {save_path}입니다.")

# 클라이언트 리스트 출력
def display_connected_clients():
    if connected_clients:
        print("[INFO] 연결된 클라이언트:")
        for addr in connected_clients.keys():
            print(f" - {addr}")
    else:
        print("[INFO] 현재 연결된 클라이언트가 없습니다.")

# 저장된 파일 리스트 출력
def display_saved_files():
    logger.info(f"저장된 파일목록 체크")
    if received_files:
        print("[INFO] 저장된 파일:")
        for idx, (file_name, addr) in enumerate(received_files, start=1):
            print(f" {idx}. {file_name} (송신자: {addr})")
    else:
        print("[INFO] 저장된 파일이 없습니다.")

def get_ip_and_port(port = data["Server_setting"]["port"]):
    try:
        # 소켓 생성
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # 외부 서버와 연결 시도 (실제 연결하지 않음, IP 확인용)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        port = data["Server_setting"]["port"] #이 한줄때문에?
        print(f"\nIP Address: {ip_address} \n \nPort: {port}")
        return ip_address, port
    except Exception as e:
        print(f"Error: {e}")
        return None, None
    
# 메인 프로그램
def main(): 
    global server_socket
    server_start_menu()
    while True:
        try:
            time.sleep(0.3)
            # 일단 지금은 timesleep 으로 땜빵하자.
            display_menu()
            choice = input("선택: ").strip()
            if choice == "1":
                server_start_menu()
            elif choice == "2":
                while True:
                    display_server_settings()
                    sub_choice = input("선택: ").strip()
                    if sub_choice == "1":
                        get_ip_and_port()
                    elif sub_choice == "2":
                        change_port()
                    elif sub_choice == "3":
                        now_path()
                    elif sub_choice == "4":
                        change_save_path()
                    elif sub_choice == "5": 
                        break
                    else:
                        print("[ERROR] 잘못된 입력입니다. WE다시 시도해주세요.")
            elif choice == "3":
                display_connected_clients()
            elif choice == "4":
                display_saved_files()
            elif choice == "5":
                check_drive_space(drive_path)
            elif choice == "6":
                print("[INFO] 프로그램을 종료합니다.")
                program_down()  # 프로그램 종료
                break
            else:
                print("[ERROR] 잘못된 입력입니다. 다시 시도해주세요.")
        except SystemExit:
            break

if __name__ == "__main__":
    main()

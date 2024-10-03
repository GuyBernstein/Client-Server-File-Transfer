from os import path
import logging

DEFAULT_PORT = 1256
PORT_FILE = "port.info"

def print_err_message(func, message):
    print(f"Error::{func.__name__} {message}")


def read_from_port_file(file_path, def_port=DEFAULT_PORT):
    if file_path is not PORT_FILE:
        print(f"should parse port from {PORT_FILE} only")
        return def_port

    if path.isfile(file_path):
        with open(file_path, 'r') as f:
            if f.readable():
                port = f.readline().strip()
                if port.isdigit() and len(port) <= 4:
                    return int(port)
                else:
                    print("invalid port. should be numbers up to 4 digits")
            else:
                print_err_message(read_from_port_file, "cant read file")
    else:
        print_err_message(read_from_port_file, "File does not exist")
    return def_port


def write_decrypted_file(file_name, decrypted_message):
    try:
        with open(file_name, 'wb') as f:
            if f.writable():
                f.write(decrypted_message)
                return True
            logging.error(f"File {file_name} is not writable.")
    except Exception as e:
        logging.exception(f"Exception while writing to file {file_name}: {e}")
    return False


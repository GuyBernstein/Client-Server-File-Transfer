from os import path

DEFAULT_PORT = 1256


def print_err_message(func, message):
    print(f"Error::{func.__name__} {message}")


def read_from_port_file(file_path, port=DEFAULT_PORT):
    if path.isfile(file_path):
        with open(file_path, 'r') as f:
            if f.readable():
                content = f.read()
                # parse port from content
                # parse port from content
                # port = parse_port(content)  # You'll need to implement this function
            else:
                print_err_message(read_from_port_file, "cant read file")
    else:
        print_err_message(read_from_port_file, "File does not exist")
    return port

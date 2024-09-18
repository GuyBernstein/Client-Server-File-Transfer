import server
import utils


if __name__ == "__main__":
    FILE_NAME = "port.info"
    port = utils.read_from_port_file(FILE_NAME)
    server = server.Server("", port)  # Host is local host like this
    server.start()



import server
import utils


if __name__ == "__main__":
    port = utils.read_from_port_file(utils.PORT_FILE)
    if port == utils.DEFAULT_PORT:
        print(f"Warning: proceeding with default port:{utils.PORT_FILE}")
    server = server.Server("localhost", port)  # Host is local host like this
    server.start()



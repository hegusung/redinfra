# Colors:
color_dict = {
    'grey': "\033[90m",
    'light_grey': "\033[37m",
    'red': "\033[91m",
    'green': "\033[92m",
    'yellow': "\033[93m",
    'blue': "\033[94m",
    'magenta': "\033[95m",
    'cyan': "\033[96m",
    'white': "\033[97m",
    'bold': "\033[1m",
}
RESET = "\033[0m"


def color(message, color):
    message = color_dict[color] + message + RESET

    return message

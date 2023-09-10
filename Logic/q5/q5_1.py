

import time
import json



def main(argv):
    if len(argv) != 1:
        raise ValueError("Wrong number of args")
    file_path = "input.json"
    with open(file_path, "r") as json_file:
        data = json.load(json_file)

    # Modify the dictionary
    data["command"] = "echo hacked"
    time.sleep(1)

    #save the changes
    with open(file_path, "w") as json_file:
        json.dump(data, json_file)
    return

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

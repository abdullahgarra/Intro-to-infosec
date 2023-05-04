def check_message(path: str) -> bool:
    """
    Return True if `msgcheck` would return 0 for the file at the specified path,
    return False otherwise.
    :param path: The file path.
    :return: True or False.
    """
    with open(path, 'rb') as reader:

        first_byte = ord(reader.read(1))
        second_byte = ord(reader.read(1)) # the second byte is saved to determine the result in the end

        number = 141
        for i in range(first_byte):
            curr_byte = reader.read(1)
            if not curr_byte:
                break
            number ^=ord( curr_byte)
        return number == second_byte

    
def main(argv):
    if len(argv) != 2:
        print('USAGE: python {} <msg-file>'.format(argv[0]))
        return -1
    path = argv[1]
    if check_message(path):
        print('valid message')
        return 0
    else:
        print('invalid message')
        return 1


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))

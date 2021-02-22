import unittest
import os
import uuid
import string
import random

class TestFS(unittest.TestCase):

    def test_create_small(self):
        FILENAME = str(uuid.uuid1())
        write_string = "ciao"
        # test create, write, read
        with open('mountdir/{}'.format(FILENAME), 'w+') as f:
            f.write(write_string)
            f.seek(0, 0);
            read_string = f.read()
            print("written string: {}\t read string: {}".format(write_string, read_string))
            self.assertEqual(read_string, write_string)
        # re-open and read
        with open('mountdir/{}'.format(FILENAME), 'r+') as f:
            read_string = f.read()
            print("written string: {}\t read string: {}".format(write_string, read_string))
            self.assertEqual(read_string, write_string)
        # test append
        with open('mountdir/{}'.format(FILENAME), 'a+') as f:
            f.write(write_string)
            f.seek(len(write_string), 0);
            read_string = f.read()
            self.assertEqual(read_string, write_string)
        # re-open and read
        with open('mountdir/{}'.format(FILENAME), 'r+') as f:
            f.seek(len(write_string), 0);
            read_string = f.read()
            print("written string: {}\t read string: {}".format(write_string, read_string))
            self.assertEqual(read_string, write_string)


    def test_create_big(self):
        """
        Try with bigger file
        """
        FILENAME = str(uuid.uuid1())
        write_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=1000000*2))
        with open('mountdir/{}'.format(FILENAME), 'w+') as f:
            f.write(write_string);
            f.seek(0, 0);
            read_string = f.read()
            self.assertEqual(read_string, write_string)



    def test_create_binary(self):
        """
        Try with binary file
        """
        FILENAME = str(uuid.uuid1())
        written_data = os.urandom(1024*1024*2) # how many kb
        with open('mountdir/{}'.format(FILENAME), 'wb') as f:
            f.write(written_data) # how many kb
        with open('mountdir/{}'.format(FILENAME), 'rb') as f:
            read_data = f.read()
        self.assertEqual(read_data, written_data)




if __name__ == '__main__':
    unittest.main()

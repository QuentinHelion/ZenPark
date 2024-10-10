"""
This file contain file usage methods
"""


class File:
    """
    File usage object
    """

    def __init__(self, path):
        self.path = path

    def update_path(self, path):
        """
        Update the path of the file
        :return:
        """
        self.path = path
        return self

    def open(self, param="x"):
        """
        :return:
        """
        return open(self.path, param)

    def read(self):
        """
        :return:
        """
        return self.open().read()

    def write(self, content):
        """
        :param content:
        :return:
        """
        return self.open("w").write(content)

    def close(self):
        """
        :return:
        """
        return self.open().close()

## @file
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import os
import struct
import sys

# python version
python_version = sys.version_info[0]

def getPath():
    fileList = []
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            continue
        if os.path.isfile(path):
            if checkFile(path):
                fileList.append(path)
        else:
            subPathList = os.listdir(path)
            for i in range(0, len(subPathList)):
                subPath = os.path.join(path, subPathList[i])
                if os.path.isfile(subPath) and checkFile(subPath):
                    fileList.append(subPath)
    if not fileList:
        print("The input is neither ktest format file nor folder that include ktest format file.\n")
        printUsage()
    return fileList

def checkFile(file):
    kTestFile = open(file, 'rb')
    kTestHeader = kTestFile.read(5)
    kTestFile.close()
    if kTestHeader == b'KTEST' or kTestHeader == b"BOUT\n":
        return True
    else:
        return False

def analyseFile(file):
    objectList = []
    kTestFile = open(file, 'rb')
    kTestFile.read(5)
    kTestVersion = struct.unpack('>i', kTestFile.read(4))[0]
    targetNum = struct.unpack('>i', kTestFile.read(4))[0]
    for i in range(targetNum):
        kTestFile.read(struct.unpack('>i', kTestFile.read(4))[0])

    if kTestVersion >= 2:
        kTestFile.read(8)

    objectNum, = struct.unpack('>i', kTestFile.read(4))
    for i in range(objectNum):
        objectName = kTestFile.read(struct.unpack('>i', kTestFile.read(4))[0])
        objectData = kTestFile.read(struct.unpack('>i', kTestFile.read(4))[0])
        if python_version == 3:
            objectName = objectName.decode()
        objectList.append([i, objectName, objectData])
    kTestFile.close()
    return objectList


def genNewName(file, objectIndex, objectName):
    return os.path.join(os.path.dirname(file),
                        objectName + str(objectIndex + 1).zfill(6),
                        os.path.basename(file).split('.')[0] + '.seed')


def genSeed(file, data):
    if not os.path.exists(os.path.dirname(file)):
        os.makedirs(os.path.dirname(file))
    seed = open(file, 'wb')
    seed.write(data)
    seed.close()

def printUsage():
    print("Usage: python TransferKtestToSeed.py [Argument]")
    print("Remove header of ktest format file, and save the new binary file as .seed file.\n")
    print("Argument:")
    print("<KtestFile>                          the path of .ktest file.")
    print("<KtestFile1> <KtestFile2> ...        the paths of .ktest files.")
    print("<KtestFolder>                        the path of folder contains .ktest file.")
    print("<KtestFolder1> <KtestFolder2> ...    the paths of folders contain .ktest file.")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage()
    elif sys.argv[1] == '-h' or sys.argv[1] == 'help' or sys.argv[1] == '--help':
        printUsage()
    else:
        fileList = getPath()

        for file in fileList:
            objectList = analyseFile(file)
            for object in objectList:
                NewFileName = genNewName(file, object[0], object[1])
                genSeed(NewFileName, object[2])
                print('generate %s done.' % NewFileName)
#Simple fuzzer to test the targets parsing of the data in the body of HTTP packets.
#Sends random bytes at random lengths in the body of the HTTP packet
#to the target. Requires python 3.

import requests
import argparse
import random
import sys
import datetime
from urllib.parse import urlparse

#Check to make sure python 3 is being used.
#For some reasonl, the check is being ignored and not printing the message
    #and then exiting if python 2 is being used.
if sys.version_info.major < 3:
    print("Please use python 3 for this program.")
    sys.exit()

maxlen = 2048

def getArgs():
    parser = argparse.ArgumentParser(description="Fuzzer for testing HTTP packets with data in the body.")
    parser.add_argument("-u", "--url", metavar="", 
                        required=True, 
                        help="Target URL. Ex. \"https://example.com/path/to/target\"")
    parser.add_argument("-p", "--port", metavar="", 
                        type=int, default=80, 
                        help="Port of the target machine/device. Default: 80.")
    parser.add_argument("-m", "--method", metavar="",
                        required=True, 
                        help="HTTP method to be tested. POST, PUT, or  DELETE.")
    parser.add_argument("-s", "--seed", metavar="", 
                        default="Because I was inverted.", 
                        help="Seed for generating random data. Default: \"Because I was inverted.\" \
                        Make sure to use quotes for the new seed.")
    parser.add_argument("-l", "--length", metavar="",
                        default=maxlen,
                        help="Max length of data that can be sent. Defaul: 2048 bytes.")
    parser.add_argument("-v", "--verbose",
                        default=0, action="count",
                        help="Runs the program in verbose mode. Warning, using this will slow down the program.")
    global args
    args = parser.parse_args()
    global method
    method = args.method


def main():
    getArgs()

    #Set variables for random input generation.
    rand = random.Random()
    seed = rand.seed(args.seed)
    byteChoice = [n for n in range(0, 256)]
    
    #parse url to get path.
    p = urlparse(args.url)
    url = p.scheme+"://"+p.netloc+":"+str(args.port)+p.path+"?"+p.query

    if p.scheme == "":
        print("Please use http:// or https:// before the url/ip address.")
        sys.exit()

    i = 0
    a = 0

    #The method below is used to try to optimise the code. 
    #This way, once the method is determined, the loop doing the fuzzing will not have to
        #parse through the methods during each iteration. This will help speed up the process.
    #The non-verbose section can be used to speed it
    #up even more.
    try:
        if args.verbose == True:
                if method.lower() == "post":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the POST method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        print("Current time: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                end="  ")
                        print("Running time: {}".format(end_time - start_time)[:-7], end="  ")
                        print("Iteration: %s" % format(i, ","), end="\r")
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.post(url, data = fuzz_data)
                if method.lower() == "put":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the PUT method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        print("Current time: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                end="  ")
                        print("Running time: {}".format(end_time - start_time)[:-7], end="  ")
                        print("Iteration: %s" % format(i, ","), end="\r")
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.put(url, data = fuzz_data)
                if method.lower() == "delete":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the DELETE method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        print("Current time: %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                end="  ")
                        print("Running time: {}".format(end_time - start_time)[:-7], end="  ")
                        print("Iteration: %s" % format(i, ","), end="\r")
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.delete(url, data = fuzz_data)
                else:
                    print("That HTTP method is not recognized or used by this program. Please enter post, put, or delete.")
                    sys.exit()

        if args.verbose == False:
                if method.lower() == "post":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the POST method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.post(url, data = fuzz_data)
                if method.lower() == "put":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the PUT method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.put(url, data = fuzz_data)
                if method.lower() == "delete":
                    print("Start time: %s" % current_time)
                    start_time = datetime.datetime.now()
                    print("Fuzzing the DELETE method...")
                    while(True):
                        i += 1
                        end_time = datetime.datetime.now()
                        randlen = rand.randint(0, int(args.length))
                        fuzz_data = bytes(rand.choices(byteChoice, k=randlen))
                        r = requests.delete(url, data = fuzz_data)
                else:
                    print("That HTTP method is not recognized or used by this program. Please enter post, put, or delete.")
                    sys.exit()

    except ConnectionRefusedError as e:
        print(e)
        a += 1
        print("\r\nThe Connection is being refused, this could be due to a crash. Check the logs and/or target.")
        #Create a file for logging.
        f = open("ConnectionRefusedError.txt", "a+")
        f.write("End time: %s" % end_time)
        f.write("\r\n")
        f.write("Iteration: %s" % i)
        f.write("\r\n")
        f.write(str(r)) 
        f.write("\r\n\r\n\r\n")
        if a == 250:
            print("Connection refused after 250 attempts. Check for crash. The program will now quit.")
            sys.exit()
    except requests.exceptions.ConnectionError as e:
        print(e)
        a += 1
        print("\r\nThe Connection is being refused, this could be due to a crash. Check the logs and/or target.",
                end="\r")
        #Create a file for logging.
        f = open("ConnectionError.txt", "a+")
        f.write("Time: %s" % end_time)
        f.write("\n\r")
        f.write("Iteration: %s" % i)
        f.write("\r\n")
        #f.write(str(r)) 
        f.write("\r\n\r\n\r\n")
        if a == 250:
            print("Connection refused after 250 attempts. Check for crash. The program will now quit.")
            sys.exit()
    except KeyboardInterrupt:
        print("\n\r\n\rUser keyboard interrupt.")
        print("The program stopped at {} at iteration {}".format(end_time.strftime("%Y-%m-%d %H:%M:%S"),
            format(i, ","))) 
    except Exception as e:
        print(e)


if __name__ == "__main__":
    #Used for tracking how long the program has been running.
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    main()

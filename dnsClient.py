import argparse # for parsing command line arguments
import socket # low level networking interface
import time
import random

class DnsClient:
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', type=int, default=5, required=False)
    parser.add_argument('-r', type=int, default=3, required=False)
    parser.add_argument('-p', type=int, default=53, required=False)

    me_group = parser.add_mutually_exclusive_group()
    me_group.add_argument('-mx', action='store_true', required=False)
    me_group.add_argument('-ns', action='store_true', required=False)

    parser.add_argument('server')
    parser.add_argument('name')

    args = parser.parse_args()
    request_type = "A"
    error = ""
    number_of_answers = 0
    number_of_authoritative_records = 0
    number_of_additional_records = 0
    query_length = 0
    auth_or_nonauth = "auth"
            
    def input(self):
        if self.args.mx:
            self.request_type = "MX"
        elif self.args.ns:
            self.request_type = "NS"

        print("DNSClient sending request for ", self.args.name)
        print("Server: ", self.args.server)
        print("Request type: ", self.request_type)

    def ip_output(self, ans):
        # get ip address
        ip_address_hex = ans[-8:]
        ip_address = ""
        hex_list = [ip_address_hex[i:i+2] for i in range(0, len(ip_address_hex), 2)]
        for i in range(3):
            ip_address += str(int(hex_list[i],16))
            if i != 2:
                ip_address += "."
        
        # get ttl 
        ttl = int(ans[12:20], 16)

        # IP <tab> [ip address] <tab> [seconds can cache] <tab> [auth | nonauth]
        print("IP\t", ip_address, "\t", str(ttl), "\t", self.auth_or_nonauth)
        return


    def mx_output(self, ans, data):
        # get alias 
        alias = ''
        # get RDLENGTH (length of record alias): [20, 23]
        rdlength = int(ans[20:24], 16)
        pointer = 24
        # MX answers have the following RDATA structure: 
        # 1. preference (16 bits unsigned integer)
        # 2. exchange - domain name of a mail server using same format as QNAME

        # find preference 
        pref = 0
        pref = int(ans[pointer:pointer+4], 16)

        pointer+=4

        while(pointer < 24 + 2*rdlength):
            # check if pointer to DNS compression 
            potential_compress = int(ans[pointer], 16)
            if ((potential_compress >> 2) & 1) & ((potential_compress >> 3) & 1):
                # compression 
                # c00c -> 12 00 12 -> 1100 0000 0000 1100 & 0011 1111 1111-> (12)_16
                pointing_at = int(ans[pointer:pointer+4], 16) & 0x3fff
                alias += self.fetch_compressed(2*pointing_at, data)
                pointer += 4 # pointer takes form of 14 bit sequence
            else:
                # get length of segment
                length = int(ans[pointer:pointer+2], 16)
                pointer += 2
                for j in range(length):
                    alias += chr(int(ans[pointer:pointer+2], 16))
                    pointer += 2
                if (pointer != 23 + 2*rdlength-1):
                    alias += '.'

        # get ttl 
        ttl = int(ans[12:20], 16)

        # MX <tab> [alias] <tab> [pref] <tab> [seconds can cache] <tab> [auth | nonauth]
        print("MX\t", alias, "\t", str(pref), "\t", str(ttl), "\t", self.auth_or_nonauth)

    def ns_output(self, ans, data):
        # get alias 
        alias = ''
        # get RDLENGTH (length of record alias): [20, 23]
        rdlength = int(ans[20:24], 16)
        pointer = 24
        while(pointer < 24 + 2*rdlength):
            # check if pointer to DNS compression 
            potential_compress = int(ans[pointer], 16)
            if ((potential_compress >> 2) & 1) & ((potential_compress >> 3) & 1):
                # compression 
                # c00c -> 12 00 12 -> 1100 0000 0000 1100 & 0011 1111 1111-> (12)_16
                pointing_at = int(ans[pointer:pointer+4], 16) & 0x3fff
                alias += self.fetch_compressed(2*pointing_at, data)
                pointer += 4 # pointer takes form of 14 bit sequence
            else:
                # get length of segment
                length = int(ans[pointer:pointer+2], 16)
                pointer += 2
                for j in range(length):
                    alias += chr(int(ans[pointer:pointer+2], 16))
                    pointer += 2
                if (pointer != 23 + 2*rdlength-1):
                    alias += '.'

        # get ttl 
        ttl = int(ans[12:20], 16)

        # NS <tab> [alias] <tab> [seconds can cache] <tab> [auth | nonauth]
        print("NS\t", alias, "\t", str(ttl), "\t", self.auth_or_nonauth)

    def cname_output(self, ans, data):
        # get alias 
        alias = ''
        # get RDLENGTH (length of record alias): [20, 23]
        rdlength = int(ans[20:24], 16)
        pointer = 24
        while(pointer < 24 + 2*rdlength):
            # check if pointer to DNS compression 
            potential_compress = int(ans[pointer], 16)
            if ((potential_compress >> 2) & 1) & ((potential_compress >> 3) & 1):
                # compression 
                # c00c -> 12 00 12 -> 1100 0000 0000 1100 & 0011 1111 1111-> (12)_16
                pointing_at = int(ans[pointer:pointer+4], 16) & 0x3fff
                alias += self.fetch_compressed(2*pointing_at, data)
                pointer += 4 # pointer takes form of 14 bit sequence
            else:
                # get length of segment
                length = int(ans[pointer:pointer+2], 16)
                pointer += 2
                for j in range(length):
                    alias += chr(int(ans[pointer:pointer+2], 16))
                    pointer += 2
                if (pointer != 23 + 2*rdlength-1):
                    alias += '.'

        # get ttl 
        ttl = int(ans[12:20], 16)

        # CNAME <tab> [alias] <tab> [seconds can cache] <tab> [auth | nonauth]
        print("CNAME\t", alias, "\t", str(ttl), "\t", self.auth_or_nonauth)

    def fetch_compressed(self, pointer, data):
        result = ''

        while(True):
            # check if pointer to DNS compression 
            potential_compress = int(data[pointer], 16)
            if ((potential_compress >> 2) & 1) & ((potential_compress >> 3) & 1):
                # compression 
                pointing_at = int(data[pointer:pointer+4], 16) & 0x3fff
                result += self.fetch_compressed(pointing_at, data)
                pointer += 4 # pointer takes form of 14 bit sequence
            else:
                # get length of segment
                length = int(data[pointer:pointer+2], 16)
                if length == 0: break
                pointer += 2
                for j in range(length):
                    result += chr(int(data[pointer:pointer+2], 16))
                    pointer += 2
                
                result += '.'
        if result[-1:] == '.': result = result[:-1]
        return result


    def set_number_of_records(self, data):
        self.number_of_answers = int(data[12:16]) # number of answers is always this range
        self.number_of_authoritative_records = int(data[16:20])
        self.number_of_additional_records = int(data[20:24])


    def make_query(self):
        query_content = ''

        # header
        query_content += str(hex(random.getrandbits(16)).lstrip("0x")).zfill(4) #ID

        # binary: 0000 00TCbit1 0000 0000 == 0x0100
        QR = '0'
        OPCODE = '0000'
        AA = '0'
        TC = '0' #assumed TC bit is 0 (not truncated)
        RD = '1'
        RA = '0'
        Z = '000'
        RCODE = '0000'
        header_second_row = QR + OPCODE + AA + TC + RD + RA + Z + RCODE
        query_content += str(hex(int(header_second_row, 2)).lstrip("0x")).zfill(4)

        QDCOUNT = '0001'
        ANCOUNT = '0000' # assumed ANCOUNT is 0
        NSCOUNT = '0000' # assumed NSCOUNT is 0
        ARCOUNT = '0000' # assumed ARCOUNT is 0
        query_content += QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

        # Question
        # QNAME 
        name_array = self.args.name.split('.')
        QNAME = ''
        for segment in name_array:
            QNAME += str(hex(len(segment)).lstrip("0x")).zfill(2)
            for character in segment:
                QNAME += str(hex(ord(character)).lstrip("0x")).zfill(2)
        QNAME += '00'
        # QTYPE
        if (self.request_type == "A"):
            QTYPE = '0001'
        elif (self.request_type == "NS"):
            QTYPE = '0002'
        else:
            QTYPE = '000f'    

        # QCLASS
        QCLASS = '0001'

        query_content += QNAME + QTYPE + QCLASS
        self.query_length = len(query_content)

        return query_content

    def make_request(self):
        server = self.args.server.lstrip('@')
        timeout = self.args.t
        max_retries = self.args.r
        port = self.args.p
        query_content = self.make_query()

        # actual query
        for i in range(max_retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                start_time = time.time()
                sent = sock.sendto(bytes.fromhex(query_content), (server, port))
                data, tuple = sock.recvfrom(4096)
                time_taken = time.time() - start_time
                print("Response received after " + str(time_taken) + " seconds ("+ str(i) + " retries)")
                data = data.hex()
                break
            except Exception as error:
                print("ERROR \t The following error is encountered at try ", (i+1), " when sending the query or receiving the response from socket: ", error)
                if i == max_retries - 1:
                    print("ERROR \t  Maximum number of retries ", max_retries, "exceeded")
                    return
        

        self.set_number_of_records(data)

        if self.number_of_answers == 0 & self.number_of_authoritative_records == 0 & self.number_of_additional_records == 0:
            print("NOTFOUND")
            return
        
        # get RA 
        # RA is set if recursive are supported and cleared if not supported
        ra_int = int(data[6], 16)
        temp = ra_int >> 3 # check if 1 _ _ _ is set
        if (temp & 0): 
            print("ERROR \t Request not supported: Server doesn't support recursive queries.")

        # get RCODE
        # 4 bit - 5 possible values 
        # 0 - no error
        # 1 - format error
        # 2 - server failure
        # 3 - name error
        # 4 - not implemented
        # 5 - refused

        rcode_int = int(data[7], 16)
        if rcode_int == 1:
            print("ERROR \t Format error: the name server was unable to interpret the query.")
            return
        elif rcode_int == 2:
            print("ERROR \t Server failure: the name server was unable to process this query due to a problem with the name server.")
            return 
        elif rcode_int == 3:
            print("NOTFOUND")
            return
        elif rcode_int == 4:
            print("ERROR \t Not implemented: the name server does not support the requested kind of query.") 
            return    
        elif rcode_int == 5:
            print("ERROR \t Refused: the name server refuses to perform the requested operation for policy reasons.")
            return
        elif rcode_int != 0: return #continue with rest of program only if RCODE = 0
        

        # get auth or nonauth 
        auth_int = int(data[5], 16)
        temp = auth_int >> 2 # check if _ 1 _ _ is set
        if (temp & 1): self.auth_or_nonauth = "auth"
        else:  self.auth_or_nonauth = "nonauth"

        # get truncated (TC)
        truncated_int = int(data[5], 16)
        temp = truncated_int >> 1 # check if _ _ 1 _ is set
        if (temp & 1): 
            print("WARNING \t Truncated message: The message was truncated because it had a length greater than that permitted by the transmission channel.")
        
        # Answer Section
        # iterate through each answer section -> 
        # determine which type of record it is and call corresponding output function
        if (self.number_of_answers > 0):
            print("***Answer Section (" + str(self.number_of_answers) + " records)***")
            start_ans = self.query_length
            end_ans = self.query_length
            for i in range(self.number_of_answers):
                # get RDLENGTH (length of record alias): [start_ans + 20, start_ans + 23]
                rdlength = int(data[start_ans+20:start_ans+24], 16)
                end_ans = start_ans + 23 + 2*rdlength

                # check CLASS 16 bit code - expect 0x0001 (if not print error message)
                class_code= data[start_ans+8:start_ans+12]
                if class_code != "0001": 
                    print("ERROR \t Unexpected response: encountered class code ", class_code, " but expected 0001.")
                    continue 
                    
                # get type of record: [start_ans + 4, start_ans + 7]  ([start:end] -> start is inclusive, end is exclusive)
                type = data[start_ans+4:start_ans+8] # number of records is always this range
                if (type == "0001"):
                    self.ip_output(data[start_ans : end_ans+1])
                elif (type == "0002"):
                    self.ns_output(data[start_ans : end_ans+1], data)
                elif (type == "000f"):
                    self.mx_output(data[start_ans : end_ans+1], data)
                elif (type == "0005"):
                    self.cname_output(data[start_ans : end_ans+1], data)
                # update start_ans for next answer if any
                start_ans = end_ans + 1

        # Authority Section 
        if self.number_of_authoritative_records > 0:
            # start_ans is already at the good place - wherever it was left from previous section
            for i in range(self.number_of_additional_records):
                # get RDLENGTH (length of record alias): [start_ans + 20, start_ans + 23]
                rdlength = int(data[start_ans+20:start_ans+24], 16)
                end_ans = start_ans + 23 + 2*rdlength
                # update start_ans for next answer if any
                start_ans = end_ans + 1   

        # Additional Information Section
        if self.number_of_additional_records > 0:
            print("***Additional Section (" + str(self.number_of_additional_records) + " records)***")
            # start_ans is already at the good place - wherever it was left from previous section
            for i in range(self.number_of_additional_records):
                # get RDLENGTH (length of record alias): [start_ans + 20, start_ans + 23]
                rdlength = int(data[start_ans+20:start_ans+24], 16)
                end_ans = start_ans + 23 + 2*rdlength

                # get type of record: [start_ans + 4, start_ans + 7]  ([start:end] -> start is inclusive, end is exclusive)
                type = data[start_ans+4:start_ans+8]
                if (type == "0001"):
                    self.ip_output(data[start_ans : end_ans+1])
                elif (type == "0002"):
                    self.ns_output(data[start_ans : end_ans+1], data)
                elif (type == "000f"):
                    self.mx_output(data[start_ans : end_ans+1], data)
                elif (type == "0005"):
                    self.cname_output(data[start_ans : end_ans+1], data)
                else:
                    print("ERROR \t Not supported record type for additional record ", (i+1), " The following type is unknown: " + type)
                # update start_ans for next answer if any
                start_ans = end_ans + 1        

if __name__ == "__main__":
    # program starts running here
    dnsClient = DnsClient()
    dnsClient.input()
    dnsClient.make_request()

import struct
import glob

def calculate_crc(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def format_hex(byte_data):
    hex_string = ''.join(f'{byte:02X}' for byte in byte_data)
    formatted_hex = ''.join(hex_string[i:i+48]
                            for i in range(0, len(hex_string), 48))
    return formatted_hex

def interpret_data(register, data):
    result = ""
    # Interpret as 32-bit floats
    if len(data) >= 4:
        floats = [struct.unpack('>f', data[i:i+4])[0] for i in range(0, len(data) - 3, 4)]
        if register == "0088000a": # Power
            result = f"P1,P2,P3,P4,P5,C1,C2,C3,C4,{','.join(map(str, floats))}"
        elif register == "00f40008":  # Current
            result = f"{','.join(map(str, floats))}\n"
        else:
            result =f"Unknown registers:{register}: {floats}\n"
    return result

def parse_modbus_rtu_message(byte_data, register, is_response=False):
    if len(byte_data) < 8:
        return "Invalid message: too short", len(byte_data), None

    address = byte_data[0]
    function_code = byte_data[1]

    if not is_response:
        # Request message
        if function_code in [0x01, 0x02, 0x03, 0x04]:  # Read functions
            data_length = 6
        elif function_code in [0x05, 0x06]:  # Single write functions
            data_length = 6
        elif function_code in [0x0F, 0x10]:  # Multiple write functions
            data_length = 7 + byte_data[6]
        else:
            data_length = len(byte_data) - 2  # Unknown function, assume all remaining data
    else:
        # Response message
        if function_code in [0x01, 0x02, 0x03, 0x04]:  # Read functions response
            data_length = 3 + byte_data[2]
        elif function_code in [0x05, 0x06, 0x0F, 0x10]:  # Write functions response
            data_length = 6
        else:
            data_length = len(byte_data) - 2  # Unknown function, assume all remaining data

    message_length = data_length + 2  # Add 2 for CRC
    if len(byte_data) < message_length:
        return "Invalid message: incomplete", len(byte_data)

    data = byte_data[2:data_length]
    crc_received = struct.unpack('<H', byte_data[data_length:message_length])[0]
    crc_calculated = calculate_crc(byte_data[:data_length])

    message_type = "Response" if is_response else "Request"
    result = ""
    if is_response and function_code == 0x03:
        register_data = data[1:]
        result = interpret_data(register, register_data)
    else:
        register = data.hex()

    if crc_received != crc_calculated:
        result = "CRC Mismatch"

    return result, message_length, register



def parse_modbus_rtu(byte_data):

    request_result, request_length,register = parse_modbus_rtu_message(byte_data, None)
    byte_data = byte_data[request_length:]
    response_result, request_length, _= parse_modbus_rtu_message(byte_data, register, is_response=True)
    byte_data = byte_data[request_length:]

    return response_result, byte_data

def parse_line(byte_data):
    result1, remaining_data = parse_modbus_rtu(byte_data)           # probably Power- but checked for registers
    result2, remaining_data = parse_modbus_rtu(remaining_data)      # probably Current - but checked for registers
    return f"{result1},{result2.rstrip()}"

def main():
    file_list = glob.glob('data*.txt')
    for file_name in file_list:
        with open(file_name, 'r') as file:
            print(f"Processing file: {file_name}")
            for line_number, line in enumerate(file, 1):
                binary_string = line.strip()
                byte_data = bytes(int(binary_string[i:i+8], 2)
                                  for i in range(0, len(binary_string), 8))
                print(parse_line(byte_data))


if __name__ == "__main__":
    main()